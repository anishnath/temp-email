#!/bin/bash
sudo apt update
sudo apt install -y golang-go postfix procmail nginx sqlite3
if [ ! -f /home/ubuntu/temp-email/config/.env ]; then
    cp /home/ubuntu/go/src/temp-email/config/.env.example /home/ubuntu/temp-email/config/.env
    echo "Please edit /home/ubuntu/temp-email/config/.env with your settings"
fi
# Create database if it doesn't exist
DB_PATH=${EMAIL_DB_PATH:-/home/ubuntu/emails.db}
if [ ! -f "$DB_PATH" ]; then
    sqlite3 "$DB_PATH" "CREATE TABLE emails (id INTEGER PRIMARY KEY AUTOINCREMENT, temp_address TEXT, sender TEXT, subject TEXT, body TEXT, received_at DATETIME DEFAULT CURRENT_TIMESTAMP, expires_at DATETIME);"
fi