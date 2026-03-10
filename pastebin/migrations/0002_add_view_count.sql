-- Add view_count to pastes (for D1 deployments)
-- Run: wrangler d1 execute pastebin-db --file=pastebin/migrations/0002_add_view_count.sql

ALTER TABLE pastes ADD COLUMN view_count INTEGER NOT NULL DEFAULT 0;
