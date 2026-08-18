// Reading Tracker — zero-dependency Node server backed by SQLite.
// Uses Node's built-in http and node:sqlite modules (Node 22.5+ / stable in 24+).

import http from 'node:http';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize } from 'node:path';
import { createClient } from '@libsql/client';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 4321;
// In production (behind HTTPS, e.g. Fly.io) set SECURE_COOKIES=1 so the session
// cookie is only sent over HTTPS.
const SECURE_COOKIES = process.env.SECURE_COOKIES === '1' || process.env.SECURE_COOKIES === 'true';
// DB_PATH lets the database live on a persistent volume in production; locally it
// defaults to a file next to this server.
const DB_PATH = process.env.DB_PATH || join(__dirname, 'reading.db');

// --- Database (libSQL / Turso) --------------------------------------------
// Uses a hosted Turso database in production (TURSO_DATABASE_URL + auth token),
// and the same-format local SQLite file otherwise — so one codebase runs both.
const client = createClient(
  process.env.TURSO_DATABASE_URL
    ? { url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN }
    : { url: `file:${DB_PATH}` }
);

// Small async helpers over the libSQL client (rows come back as plain objects).
async function dbAll(sql, args = []) {
  const r = await client.execute({ sql, args });
  return r.rows.map((row) => ({ ...row }));
}
async function dbGet(sql, args = []) {
  return (await dbAll(sql, args))[0];
}
async function dbRun(sql, args = []) {
  const r = await client.execute({ sql, args });
  return {
    lastInsertRowid: r.lastInsertRowid == null ? undefined : Number(r.lastInsertRowid),
    changes: Number(r.rowsAffected ?? 0),
  };
}

// Create the schema and run column migrations. Awaited before the server listens.
async function initDb() {
  await client.executeMultiple(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    NOT NULL UNIQUE,
      password_hash TEXT    NOT NULL,
      created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash  TEXT    PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS entries (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title       TEXT    NOT NULL,
      type        TEXT    NOT NULL DEFAULT 'book',
      author      TEXT    NOT NULL DEFAULT '',
      status      TEXT    NOT NULL DEFAULT 'want',
      reflections TEXT    NOT NULL DEFAULT '',
      cover_url   TEXT    NOT NULL DEFAULT '',
      pages       INTEGER NOT NULL DEFAULT 0,
      position    INTEGER NOT NULL DEFAULT 0,
      created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
      updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS notes (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      entry_id   INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
      parent_id  INTEGER REFERENCES notes(id) ON DELETE CASCADE,
      body       TEXT    NOT NULL,
      created_at TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
    );

    CREATE INDEX IF NOT EXISTS idx_notes_entry ON notes(entry_id);
  `);

  // Column migrations for databases created before a given feature existed.
  const addColumnIfMissing = async (table, column, ddl) => {
    const cols = await dbAll(`PRAGMA table_info(${table})`);
    if (!cols.some((c) => c.name === column)) await client.execute(ddl);
  };
  await addColumnIfMissing('notes', 'parent_id', 'ALTER TABLE notes ADD COLUMN parent_id INTEGER REFERENCES notes(id)');
  await addColumnIfMissing('entries', 'cover_url', "ALTER TABLE entries ADD COLUMN cover_url TEXT NOT NULL DEFAULT ''");
  await addColumnIfMissing('entries', 'pages', 'ALTER TABLE entries ADD COLUMN pages INTEGER NOT NULL DEFAULT 0');
  await addColumnIfMissing('entries', 'user_id', 'ALTER TABLE entries ADD COLUMN user_id INTEGER REFERENCES users(id)');

  // Manual shelf order. When first added, seed positions per user by recency so
  // "My arrangement" starts out matching the recently-updated view.
  {
    const hasPosition = (await dbAll('PRAGMA table_info(entries)')).some((c) => c.name === 'position');
    if (!hasPosition) {
      await client.execute('ALTER TABLE entries ADD COLUMN position INTEGER NOT NULL DEFAULT 0');
      const rows = await dbAll('SELECT id, user_id FROM entries ORDER BY user_id, updated_at DESC, id DESC');
      const counter = {};
      for (const r of rows) {
        const k = r.user_id ?? 'null';
        counter[k] = counter[k] ?? 0;
        await dbRun('UPDATE entries SET position = ? WHERE id = ?', [counter[k], r.id]);
        counter[k]++;
      }
    }
  }

  // Fold any legacy single "reflections" text into the notes log.
  const legacy = await dbAll(`SELECT id, reflections, created_at FROM entries WHERE TRIM(reflections) <> ''`);
  for (const e of legacy) {
    await dbRun('INSERT INTO notes (entry_id, body, created_at) VALUES (?, ?, ?)', [e.id, e.reflections, e.created_at]);
    await dbRun('UPDATE entries SET reflections = ? WHERE id = ?', ['', e.id]);
  }
}

const VALID_TYPES = new Set(['book', 'article', 'paper', 'other']);
const VALID_STATUS = new Set(['want', 'reading', 'finished']);

// --- Helpers --------------------------------------------------------------
function sendJSON(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1e6) reject(new Error('Payload too large'));
    });
    req.on('end', () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

// --- Auth -----------------------------------------------------------------
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 days
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// Passwords are stored as "saltHex:scryptHex" — never plaintext.
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(password, salt, 64);
  return `${salt.toString('hex')}:${dk.toString('hex')}`;
}
function verifyPassword(password, stored) {
  const [saltHex, hashHex] = String(stored).split(':');
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const dk = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
  return dk.length === expected.length && crypto.timingSafeEqual(dk, expected);
}

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

// Create a session, return the raw token (only its hash is stored).
async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await dbRun('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
    [sha256(token), userId, Date.now() + SESSION_TTL_MS]);
  return token;
}
const COOKIE_SECURE = SECURE_COOKIES ? '; Secure' : '';
function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie',
    `sid=${token}; HttpOnly; Path=/; SameSite=Lax${COOKIE_SECURE}; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `sid=; HttpOnly; Path=/; SameSite=Lax${COOKIE_SECURE}; Max-Age=0`);
}

// Resolve the logged-in user from the session cookie, or null.
async function currentUser(req) {
  const token = parseCookies(req).sid;
  if (!token) return null;
  const row = await dbGet(
    `SELECT s.expires_at, u.id, u.username
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?`,
    [sha256(token)]
  );
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    await dbRun('DELETE FROM sessions WHERE token_hash = ?', [sha256(token)]);
    return null;
  }
  return { id: row.id, username: row.username };
}

async function registerUser(input, res) {
  const username = String(input.username ?? '').trim().toLowerCase();
  const password = String(input.password ?? '');
  if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
    throw { code: 400, message: 'Username must be 3–32 characters: letters, numbers, . _ -' };
  }
  if (password.length < 8) throw { code: 400, message: 'Password must be at least 8 characters' };
  if (await dbGet('SELECT 1 FROM users WHERE username = ?', [username])) {
    throw { code: 409, message: 'That username is already taken' };
  }
  const firstUser = (await dbGet('SELECT COUNT(*) AS c FROM users')).c === 0;
  const info = await dbRun('INSERT INTO users (username, password_hash) VALUES (?, ?)',
    [username, hashPassword(password)]);
  const userId = Number(info.lastInsertRowid);
  // The very first account inherits any pre-existing, unowned library.
  if (firstUser) await dbRun('UPDATE entries SET user_id = ? WHERE user_id IS NULL', [userId]);
  setSessionCookie(res, await createSession(userId));
  return { user: { id: userId, username } };
}

async function loginUser(input, res) {
  const username = String(input.username ?? '').trim().toLowerCase();
  const password = String(input.password ?? '');
  const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
  // Same generic error whether the username or the password is wrong.
  if (!user || !verifyPassword(password, user.password_hash)) {
    throw { code: 401, message: 'Invalid username or password' };
  }
  setSessionCookie(res, await createSession(user.id));
  return { user: { id: user.id, username: user.username } };
}

async function logoutUser(req, res) {
  const token = parseCookies(req).sid;
  if (token) await dbRun('DELETE FROM sessions WHERE token_hash = ?', [sha256(token)]);
  clearSessionCookie(res);
  return { ok: true };
}

function sanitize(input) {
  const title = String(input.title ?? '').trim();
  let type = String(input.type ?? 'book').trim();
  let status = String(input.status ?? 'want').trim();
  const author = String(input.author ?? '').trim();
  let cover_url = String(input.cover_url ?? '').trim();
  let pages = parseInt(input.pages, 10);
  if (!VALID_TYPES.has(type)) type = 'other';
  if (!VALID_STATUS.has(status)) status = 'want';
  // Only allow http(s) image URLs to be stored as a cover.
  if (!/^https?:\/\//i.test(cover_url)) cover_url = '';
  if (!Number.isFinite(pages) || pages < 0 || pages > 100000) pages = 0;
  return { title, type, author, status, cover_url, pages };
}

async function attachNotes(entries) {
  if (entries.length === 0) return entries;
  const ids = entries.map((e) => e.id);
  const placeholders = ids.map(() => '?').join(',');
  const notes = await dbAll(
    `SELECT * FROM notes WHERE entry_id IN (${placeholders})
     ORDER BY created_at ASC, id ASC`,
    ids
  );

  // Root notes (parent_id IS NULL) each carry a chronological list of follow-ups.
  const rootsByEntry = {};
  const followupsByRoot = {};
  for (const n of notes) {
    if (n.parent_id == null) {
      n.followups = [];
      (rootsByEntry[n.entry_id] ||= []).push(n);
    } else {
      (followupsByRoot[n.parent_id] ||= []).push(n);
    }
  }
  for (const e of entries) {
    const roots = rootsByEntry[e.id] || [];
    for (const r of roots) r.followups = followupsByRoot[r.id] || [];
    e.notes = roots;
  }
  return entries;
}

// --- Entry handlers -------------------------------------------------------
// Every query is scoped to `userId`. Access to another user's row simply finds
// nothing (→ 404), so entries are isolated at the database layer, not the UI.
async function listEntries(userId, search) {
  let rows;
  if (search && search.trim()) {
    const q = `%${search.trim()}%`;
    rows = await dbAll(
      `SELECT * FROM entries
        WHERE user_id = ?
          AND (title LIKE ? OR author LIKE ?
               OR id IN (SELECT entry_id FROM notes WHERE body LIKE ?))
        ORDER BY updated_at DESC`,
      [userId, q, q, q]
    );
  } else {
    rows = await dbAll('SELECT * FROM entries WHERE user_id = ? ORDER BY updated_at DESC', [userId]);
  }
  return attachNotes(rows);
}

async function getEntry(userId, id) {
  const row = await dbGet('SELECT * FROM entries WHERE id = ? AND user_id = ?', [id, userId]);
  if (!row) return null;
  return (await attachNotes([row]))[0];
}

async function createEntry(userId, input) {
  const e = sanitize(input);
  if (!e.title) throw { code: 400, message: 'Title is required' };
  const { m } = await dbGet('SELECT COALESCE(MAX(position), -1) AS m FROM entries WHERE user_id = ?', [userId]);
  const info = await dbRun(
    `INSERT INTO entries (user_id, title, type, author, status, cover_url, pages, position)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [userId, e.title, e.type, e.author, e.status, e.cover_url, e.pages, Number(m) + 1]
  );
  return getEntry(userId, info.lastInsertRowid);
}

// Save a manual left-to-right arrangement of the user's books.
async function reorderEntries(userId, order) {
  if (!Array.isArray(order)) throw { code: 400, message: 'order must be an array of ids' };
  let pos = 0;
  for (const rawId of order) {
    const id = Number(rawId);
    if (!Number.isInteger(id)) continue;
    await dbRun('UPDATE entries SET position = ? WHERE id = ? AND user_id = ?', [pos, id, userId]);
    pos++;
  }
  return { ok: true };
}

async function updateEntry(userId, id, input) {
  const existing = await dbGet('SELECT * FROM entries WHERE id = ? AND user_id = ?', [id, userId]);
  if (!existing) throw { code: 404, message: 'Entry not found' };
  const e = sanitize({
    title: input.title ?? existing.title,
    type: input.type ?? existing.type,
    author: input.author ?? existing.author,
    status: input.status ?? existing.status,
    cover_url: input.cover_url ?? existing.cover_url,
    pages: input.pages ?? existing.pages,
  });
  if (!e.title) throw { code: 400, message: 'Title is required' };
  await dbRun(
    `UPDATE entries
     SET title = ?, type = ?, author = ?, status = ?, cover_url = ?, pages = ?, updated_at = datetime('now')
     WHERE id = ? AND user_id = ?`,
    [e.title, e.type, e.author, e.status, e.cover_url, e.pages, id, userId]
  );
  return getEntry(userId, id);
}

async function deleteEntry(userId, id) {
  const info = await dbRun('DELETE FROM entries WHERE id = ? AND user_id = ?', [id, userId]);
  if (info.changes === 0) throw { code: 404, message: 'Entry not found' };
  return { ok: true };
}

// --- Note handlers --------------------------------------------------------
// A note is owned by whoever owns its entry; every check joins back to entries.
async function ownsEntry(userId, entryId) {
  return !!(await dbGet('SELECT 1 FROM entries WHERE id = ? AND user_id = ?', [entryId, userId]));
}

async function addNote(userId, entryId, input) {
  if (!(await ownsEntry(userId, entryId))) throw { code: 404, message: 'Entry not found' };
  const body = String(input.body ?? '').trim();
  if (!body) throw { code: 400, message: 'Note cannot be empty' };
  const info = await dbRun(
    `INSERT INTO notes (entry_id, body, created_at) VALUES (?, ?, datetime('now','localtime'))`,
    [entryId, body]
  );
  await dbRun(`UPDATE entries SET updated_at = datetime('now') WHERE id = ?`, [entryId]);
  return dbGet('SELECT * FROM notes WHERE id = ?', [info.lastInsertRowid]);
}

// Add a follow-up that layers on top of an existing note (one level deep).
async function addFollowup(userId, noteId, input) {
  const target = await dbGet(
    `SELECT n.* FROM notes n JOIN entries e ON e.id = n.entry_id
      WHERE n.id = ? AND e.user_id = ?`,
    [noteId, userId]
  );
  if (!target) throw { code: 404, message: 'Note not found' };
  const body = String(input.body ?? '').trim();
  if (!body) throw { code: 400, message: 'Note cannot be empty' };
  const rootId = target.parent_id == null ? target.id : target.parent_id;
  const info = await dbRun(
    `INSERT INTO notes (entry_id, parent_id, body, created_at)
     VALUES (?, ?, ?, datetime('now','localtime'))`,
    [target.entry_id, rootId, body]
  );
  await dbRun(`UPDATE entries SET updated_at = datetime('now') WHERE id = ?`, [target.entry_id]);
  return dbGet('SELECT * FROM notes WHERE id = ?', [info.lastInsertRowid]);
}

async function deleteNote(userId, noteId) {
  const target = await dbGet(
    `SELECT n.id FROM notes n JOIN entries e ON e.id = n.entry_id
      WHERE n.id = ? AND e.user_id = ?`,
    [noteId, userId]
  );
  if (!target) throw { code: 404, message: 'Note not found' };
  await dbRun('DELETE FROM notes WHERE id = ? OR parent_id = ?', [noteId, noteId]);
  return { ok: true };
}

// --- Book lookup ----------------------------------------------------------
// Looks a title up in a free books API to suggest author + cover art.
// Always resolves (never throws) so a failed lookup can never block a save.
async function fetchJSON(url, timeoutMs = 7000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { 'User-Agent': 'ReadingTracker/1.0 (personal use)' },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

// Study-guide / summary editions pollute results and list the guide's publisher
// as the "author" (e.g. Gale Cengage, SuperSummary). Filter them out.
const JUNK_AUTHORS = /(gale|cengage|supersummary|sparknotes|bookrags|cliffs?notes|course hero|bright summaries|quicklet|litchart|shmoop|bookcaps|maxnotes|bookhabits)/i;
const JUNK_TITLE = /(study guide|sparknotes|cliffs?notes|litchart|quicklet|\bsummary\b|\bsummaries\b|a guide (for|to)|workbook)/i;
function isJunkDoc(d) {
  return JUNK_TITLE.test(d.title || '') || JUNK_AUTHORS.test((d.author_name || []).join(' '));
}

// Pick the best doc. Relevance alone is unreliable: the top hit is often an
// adaptation, a study guide, or (for foreign works) a translation whose title
// won't match the English query. So we drop junk editions, then prefer an exact
// title match, then fall back to the work with the most editions — which is
// almost always the canonical one (this also rescues works whose primary title
// is in another script, e.g. Murakami's 海辺のカフカ for "Kafka on the Shore").
function pickBestDoc(docs, q) {
  const nq = norm(q);
  let pool = docs.filter((d) => d.author_name && d.author_name.length && !isJunkDoc(d));
  if (!pool.length) pool = docs.filter((d) => d.author_name && d.author_name.length);
  if (!pool.length) pool = docs.slice();
  const exact = pool.filter((d) => norm(d.title) === nq);
  const starts = pool.filter((d) => norm(d.title).startsWith(nq));
  const chosen = exact.length ? exact : (starts.length ? starts : pool);
  chosen.sort((a, b) => (b.edition_count || 0) - (a.edition_count || 0));
  return chosen[0];
}

// Non-Latin scripts (CJK, Kana, Hangul, Cyrillic, Greek, Arabic, Hebrew…).
const NON_LATIN = /[Ͱ-ԯ֐-ۿ぀-ヿ㐀-鿿가-힯]/;
const isLatinName = (s) => !!s && /[A-Za-z]/.test(s) && !NON_LATIN.test(s);
// "Murakami, Haruki" -> "Haruki Murakami".
function tidyName(s) {
  s = String(s).trim();
  const parts = s.split(',');
  if (parts.length === 2 && parts[0].trim() && parts[1].trim()) {
    s = `${parts[1].trim()} ${parts[0].trim()}`;
  }
  return s.replace(/\s+/g, ' ').trim();
}

// Resolve an Open Library author key to an English/Latin name.
async function resolveEnglishName(key) {
  if (!key) return '';
  const a = await fetchJSON(`https://openlibrary.org/authors/${encodeURIComponent(key)}.json`);
  if (!a) return '';
  const candidates = [];
  if (a.personal_name) candidates.push(a.personal_name);
  if (Array.isArray(a.alternate_names)) candidates.push(...a.alternate_names);
  if (a.name) candidates.push(a.name);
  const latin = candidates.filter(isLatinName);
  const nice = latin.find((n) => n !== n.toUpperCase()) || latin[0]; // avoid ALL-CAPS
  return nice ? tidyName(nice) : '';
}

// Ensure an English/Latin author name. Two cases handled:
//  • The name is stored in its original script (村上春樹) → resolve to Latin.
//  • For translated classics the array is [translator (Latin), original author
//    (non-Latin)]; the non-Latin entry is the real author, so prefer it and
//    resolve THAT to English (gives Dostoevsky, not his translator).
async function englishAuthorName(doc) {
  const names = doc.author_name || [];
  const keys = doc.author_key || [];
  if (!names.length) return '';
  const nonLatinIdx = names.findIndex((n) => NON_LATIN.test(n));
  if (nonLatinIdx === -1) return tidyName(names[0]); // all Latin — take primary
  const resolved = await resolveEnglishName(keys[nonLatinIdx]);
  if (resolved) return resolved;
  // Fall back to any Latin name already in the array, else the raw name.
  const latinInArray = names.find(isLatinName);
  return tidyName(latinInArray || names[nonLatinIdx]);
}

// Return up to `max` distinct candidate matches for a title, each with an
// English author, a cover, and a year — so the UI can offer a chooser. The best
// guess is candidates[0]; the rest are alternatives (other editions/books that
// share the title). Never throws.
async function lookupBook(title, max = 4) {
  const q = String(title || '').trim();
  if (!q) return { found: false, candidates: [] };

  // 1) Open Library — general q= search so foreign-titled works surface too.
  const ol = await fetchJSON(
    `https://openlibrary.org/search.json?q=${encodeURIComponent(q)}` +
      `&limit=10&fields=title,author_name,author_key,cover_i,edition_count,first_publish_year,number_of_pages_median`
  );
  let docs = ((ol && ol.docs) || []).filter(
    (d) => d.author_name && d.author_name.length && !isJunkDoc(d)
  );

  // De-duplicate the same work appearing as several editions; keep the one with
  // the most editions per (title, author).
  const byKey = new Map();
  for (const d of docs) {
    const key = norm(d.title) + '|' + ((d.author_key && d.author_key[0]) || d.author_name[0] || '');
    const prev = byKey.get(key);
    if (!prev || (d.edition_count || 0) > (prev.edition_count || 0)) byKey.set(key, d);
  }
  const nq = norm(q);
  const uniq = [...byKey.values()].sort((a, b) => {
    // Exact title matches first, then by number of editions (canonical works).
    const ax = norm(a.title) === nq ? 1 : 0, bx = norm(b.title) === nq ? 1 : 0;
    return (bx - ax) || ((b.edition_count || 0) - (a.edition_count || 0));
  }).slice(0, max);

  const candidates = [];
  for (const d of uniq) {
    candidates.push({
      source: 'Open Library',
      title: d.title || q,
      author: await englishAuthorName(d),
      cover_url: d.cover_i ? `https://covers.openlibrary.org/b/id/${d.cover_i}-M.jpg` : '',
      year: d.first_publish_year || null,
      pages: d.number_of_pages_median || null,
    });
  }
  if (candidates.length) return { found: true, candidates };

  // 2) Google Books fallback — key-free basic volume search.
  const gb = await fetchJSON(
    `https://www.googleapis.com/books/v1/volumes?q=intitle:${encodeURIComponent(q)}&maxResults=${max}`
  );
  for (const it of ((gb && gb.items) || [])) {
    const v = it.volumeInfo || {};
    const img = v.imageLinks && (v.imageLinks.thumbnail || v.imageLinks.smallThumbnail);
    candidates.push({
      source: 'Google Books',
      title: v.title || q,
      author: tidyName((v.authors && v.authors[0]) || ''),
      cover_url: img ? img.replace(/^http:/, 'https:') : '',
      year: v.publishedDate ? parseInt(v.publishedDate, 10) || null : null,
      pages: v.pageCount || null,
    });
  }
  return { found: candidates.length > 0, candidates };
}

// --- Static file serving --------------------------------------------------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
};

async function serveStatic(req, res) {
  let urlPath = req.url === '/' ? '/index.html' : req.url.split('?')[0];
  const safePath = normalize(urlPath).replace(/^(\.\.[/\\])+/, '');
  const filePath = join(__dirname, 'public', safePath);
  if (!filePath.startsWith(join(__dirname, 'public'))) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  try {
    const data = await readFile(filePath);
    const ext = filePath.slice(filePath.lastIndexOf('.'));
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end('Not found');
  }
}

// --- Router ---------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const { method } = req;
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;

  try {
    // ---- Public auth routes ----
    if (path === '/api/register' && method === 'POST') {
      return sendJSON(res, 201, await registerUser(await readBody(req), res));
    }
    if (path === '/api/login' && method === 'POST') {
      return sendJSON(res, 200, await loginUser(await readBody(req), res));
    }
    if (path === '/api/logout' && method === 'POST') {
      return sendJSON(res, 200, await logoutUser(req, res));
    }
    if (path === '/api/me' && method === 'GET') {
      const u = await currentUser(req);
      return u ? sendJSON(res, 200, { user: u }) : sendJSON(res, 401, { error: 'Not logged in' });
    }

    // ---- Everything else under /api requires a logged-in user ----
    if (path.startsWith('/api/')) {
      const user = await currentUser(req);
      if (!user) return sendJSON(res, 401, { error: 'Not logged in' });

      if (path === '/api/entries' && method === 'GET') {
        return sendJSON(res, 200, await listEntries(user.id, url.searchParams.get('search')));
      }
      if (path === '/api/entries' && method === 'POST') {
        return sendJSON(res, 201, await createEntry(user.id, await readBody(req)));
      }
      if (path === '/api/book-lookup' && method === 'GET') {
        return sendJSON(res, 200, await lookupBook(url.searchParams.get('title')));
      }
      if (path === '/api/entries/reorder' && method === 'POST') {
        return sendJSON(res, 200, await reorderEntries(user.id, (await readBody(req)).order));
      }

      const noteAdd = path.match(/^\/api\/entries\/(\d+)\/notes$/);
      if (noteAdd && method === 'POST') {
        return sendJSON(res, 201, await addNote(user.id, Number(noteAdd[1]), await readBody(req)));
      }

      const followup = path.match(/^\/api\/notes\/(\d+)\/followups$/);
      if (followup && method === 'POST') {
        return sendJSON(res, 201, await addFollowup(user.id, Number(followup[1]), await readBody(req)));
      }

      const note = path.match(/^\/api\/notes\/(\d+)$/);
      if (note && method === 'DELETE') {
        return sendJSON(res, 200, await deleteNote(user.id, Number(note[1])));
      }

      const entry = path.match(/^\/api\/entries\/(\d+)$/);
      if (entry) {
        const id = Number(entry[1]);
        if (method === 'PUT') return sendJSON(res, 200, await updateEntry(user.id, id, await readBody(req)));
        if (method === 'DELETE') return sendJSON(res, 200, await deleteEntry(user.id, id));
      }

      return sendJSON(res, 404, { error: 'Not found' });
    }

    return serveStatic(req, res);
  } catch (err) {
    const code = err.code && Number.isInteger(err.code) ? err.code : 400;
    sendJSON(res, code, { error: err.message || 'Server error' });
  }
});

// Initialise the database schema, then start listening.
initDb()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`\n  📚 Reading Tracker running on port ${PORT}\n`);
      console.log(`  Database: ${process.env.TURSO_DATABASE_URL ? 'Turso (remote)' : DB_PATH}`);
      console.log(`  Secure cookies: ${SECURE_COOKIES ? 'on' : 'off'}`);
      console.log(`  Press Ctrl+C to stop.\n`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialise database:', err);
    process.exit(1);
  });
