-- Pastebin D1 schema
-- Run: wrangler d1 execute pastebin-db --file=pastebin/migrations/0001_init.sql

CREATE TABLE IF NOT EXISTS pastes (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL CHECK (type IN ('text', 'file')),
  filename TEXT,
  content_type TEXT,
  size INTEGER NOT NULL DEFAULT 0,
  title TEXT,
  syntax TEXT,
  visibility TEXT DEFAULT 'unlisted' CHECK (visibility IN ('public', 'unlisted', 'private')),
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  encrypted INTEGER DEFAULT 0,
  burn_after_read INTEGER DEFAULT 0,
  session_id TEXT,
  api_key_id TEXT,
  delete_token_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_pastes_expires ON pastes(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pastes_created ON pastes(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pastes_session ON pastes(session_id) WHERE session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pastes_api_key ON pastes(api_key_id) WHERE api_key_id IS NOT NULL;
