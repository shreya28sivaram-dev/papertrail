# 📚 Papertrail

A personal reading tracker with a **real database**. Track books, articles, papers,
and other media — what you want to read, what you're reading, and what you've
finished — plus your takeaways and reflections on each.

Data is stored in a local SQLite file (`reading.db`), so everything persists when
you close and reopen the app.

## Requirements

- **Node.js 22.5 or newer** (uses the built-in `node:sqlite` module).
  Check with `node --version`. No `npm install` needed — zero dependencies.

## Running it

From this folder:

```bash
node server.js
```

Then open **http://localhost:4321** in your browser.

To stop the server, press `Ctrl+C` in the terminal.

## Accounts (multi-user)

The app is multi-user. Each person **creates their own account** (username + password)
and sees only their own library — enforced on the server, per database row, not just
hidden in the UI.

- **First run:** open the app, choose **Create account**. The very first account
  created **inherits any pre-existing, unowned entries** (i.e. the library from before
  accounts existed). So whoever owns this install should register first.
- Passwords are hashed with **scrypt + a random per-user salt** — plaintext is never
  stored. Login is verified with a timing-safe comparison.
- You stay logged in via an **HttpOnly, SameSite=Lax session cookie** (only a hash of
  the session token is stored server-side). Sessions last 30 days; **Log out** ends them.
- Because the app runs over plain `http://localhost`, the cookie is not marked
  `Secure`. If you ever host this beyond localhost, put it behind HTTPS and add the
  `Secure` flag.

## Features

- **Add / edit / delete** entries.
- Fields: **title**, **type** (book / article / paper / other media),
  **author or source**, and **status** (want to read / currently reading / finished).
- A **dated notes log** on every entry (any status). Add a timestamped thought or
  reflection whenever you want — while reading, not just when finished — right from
  the entry's card. Tip: Cmd/Ctrl+Enter in the note box saves it.
- **Threaded follow-ups**: instead of editing a note, layer a follow-up on top of it.
  The original stays put and each revisit stacks beneath it on a connected timeline,
  so a single note becomes a record of how your thinking evolved. Deleting a root note
  removes its whole thread; individual notes and follow-ups can be deleted with the ×.
- **Search** across titles, authors, and note text.
- **Reflections view** (toggle at the top): steps back from the book-by-book list to
  show the *shape of your thinking* across everything —
  - all your notes and follow-ups as one stream, newest first, each tagged with its source;
  - **"What you keep coming back to"** — recurring themes pulled from your own words as
    clickable chips; click one to see every thought touching it (with the word highlighted);
  - a summary of your reflective activity (thoughts logged, entries explored, days reflecting).
  It reads only your own notes, locally — no AI or cloud.
- **Filter** by status and type.
- Live counts of what you want to read, are reading, and have finished.

## Where your data lives

Everything is in `reading.db` (a SQLite database file) in this folder. Back it up by
copying that file. To start over from scratch, stop the server, delete `reading.db`,
and start the server again — it recreates the table automatically.

## Notes

- The server listens on port `4321` by default. To use a different port:
  `PORT=8080 node server.js`.
- It's a local, single-user app — it binds to your machine and has no accounts or auth.
