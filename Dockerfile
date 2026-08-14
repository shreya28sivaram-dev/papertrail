# Node 24 — node:sqlite/libsql run cleanly here.
FROM node:24-slim

WORKDIR /app

# Install dependencies (now that we use @libsql/client).
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY server.js ./
COPY public ./public

ENV NODE_ENV=production
# All other config comes from host env vars:
#   TURSO_DATABASE_URL, TURSO_AUTH_TOKEN, SECURE_COOKIES=1, PORT (host-provided)
EXPOSE 8080
CMD ["node", "server.js"]
