#!/bin/bash
DB_PATH=${EMAIL_DB_PATH:-/home/ubuntu/emails.db}
sqlite3 "$DB_PATH" "DELETE FROM emails WHERE expires_at < datetime('now')"