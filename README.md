Setup Instructions for Ubuntu
1. Install Dependencies
   Log in to your Ubuntu server via SSH:

bash

Copy
ssh ubuntu@<your-server-ip>
Install required packages (Go, Postfix, Procmail, Nginx, SQLite):

bash

Copy
sudo apt update
sudo apt install -y golang-go postfix procmail nginx sqlite3
Postfix Configuration: During Postfix installation, choose Internet Site and set the mail name to yourtempemail.com.
2. Set Up Go Workspace
   Create the monorepo directory:

bash

Copy
mkdir -p /home/ubuntu/go/src/temp-email
cd /home/ubuntu/go/src/temp-email
go mod init temp-email
3. Create Environment Variables
   Copy the .env.example file (provided below) and edit it:

bash

Copy
cp config/.env.example config/.env
vim config/.env
Set:

text

Copy
EMAIL_DB_PATH=/home/ubuntu/emails.db
EMAIL_DOMAIN=yourtempemail.com
4. Configure Postfix
   Edit /etc/postfix/main.cf:

bash

Copy
sudo vim /etc/postfix/main.cf
Add or update:

text

Copy
myhostname = yourtempemail.com
mydestination = $myhostname, localhost.$mydomain, localhost
inet_interfaces = all
inet_protocols = ipv4
virtual_alias_maps = hash:/etc/postfix/virtual
Set up a catch-all in /etc/postfix/virtual:

bash

Copy
sudo vim /etc/postfix/virtual
Add:

text

Copy
@yourtempemail.com ubuntu
Update Postfix mappings and restart:

bash

Copy
sudo postmap /etc/postfix/virtual
sudo systemctl restart postfix
5. Set Up Procmail
   Ensure Procmail pipes emails to the email processor:

bash

Copy
echo ':0\n| /home/ubuntu/go/bin/process-email' > /home/ubuntu/.procmailrc
6. Configure Nginx
   Create an Nginx configuration:

bash

Copy
sudo vim /etc/nginx/sites-available/temp-email
Add:

text

Copy
server {
listen 80;
server_name yourtempemail.com;
location / {
root /home/ubuntu/go/src/temp-email/static;
}
location /generate {
proxy_pass http://localhost:8080;
}
location /inbox/ {
proxy_pass http://localhost:8080;
}
}
Enable the site and restart Nginx:

bash

Copy
sudo ln -s /etc/nginx/sites-available/temp-email /etc/nginx/sites-enabled/
sudo systemctl restart nginx
7. Create SQLite Database
   Create the database:

bash

Copy
sqlite3 /home/ubuntu/emails.db
Run:

sql

Copy
CREATE TABLE emails (
id INTEGER PRIMARY KEY AUTOINCREMENT,
temp_address TEXT,
sender TEXT,
subject TEXT,
body TEXT,
received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
expires_at DATETIME
);
.exit