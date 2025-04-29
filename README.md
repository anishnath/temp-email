Setup Instructions for Ubuntu
1. Install Dependencies
   Log in to your Ubuntu server via SSH:

Linux Build 
```bash
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o bin/temp-email ./cmd/api
````

RHEL 
```bash
sudo yum install -y postfix
sudo vim /etc/postfix/main.cf
myhostname = yourtempemail.com
mydestination = $myhostname, localhost.$mydomain, localhost
inet_interfaces = all
inet_protocols = ipv4

Edit /etc/postfix/virtual:
@yourtempemail.com ec2-user

MAP IT 
sudo postmap /etc/postfix/virtual
sudo postconf -e "virtual_alias_maps = hash:/etc/postfix/virtual"


sudo systemctl start postfix
sudo systemctl enable postfix
```

```bash
ssh ubuntu@<your-server-ip>
````
Install required packages (Go, Postfix, Procmail, Nginx, SQLite):


```bash
sudo apt update
sudo apt install -y golang-go postfix procmail  sqlite3
```

Postfix Configuration: During Postfix installation, choose Internet Site and set the mail name to yourtempemail.com.
2. Set Up Go Workspace
   Create the monorepo directory:

```bash
mkdir -p /home/ubuntu/go/src/temp-email
cd /home/ubuntu/go/src/temp-email
go mod init temp-email
```

3. Create Environment Variables
   Copy the .env.example file (provided below) and edit it:

```bash
cp config/.env.example config/.env
vim config/.env
```
Set:

```text
EMAIL_DB_PATH=/home/ubuntu/emails.db
EMAIL_DOMAIN=yourtempemail.com
```

4. Configure Postfix
   Edit /etc/postfix/main.cf:

```bash
sudo vim /etc/postfix/main.cf
```
Add or update:

```text
myhostname = yourtempemail.com
mydestination = $myhostname, localhost.$mydomain, localhost
inet_interfaces = all
inet_protocols = ipv4
virtual_alias_maps = hash:/etc/postfix/virtual
```
Set up a catch-all in /etc/postfix/virtual:

```bash
sudo vim /etc/postfix/virtual
```
Add:

```text
@yourtempemail.com ubuntu
```
Update Postfix mappings and restart:


```bash
sudo postmap /etc/postfix/virtual
sudo systemctl restart postfix
```

5. Set Up Procmail
   Ensure Procmail pipes emails to the email processor:

```bash
echo ':0\n| /home/ubuntu/go/bin/process-email' > /home/ubuntu/.procmailrc
```

7. Create SQLite Database
   Create the database:

```bash
sqlite3 /home/ubuntu/emails.db
```
Run:

```sql
CREATE TABLE emails (
id INTEGER PRIMARY KEY AUTOINCREMENT,
temp_address TEXT,
sender TEXT,
subject TEXT,
body TEXT,
received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
expires_at DATETIME
);
```


### Working config 
`cat /etc/postfix/main.cf`
```text

# See /usr/share/postfix/main.cf.dist for a commented, more complete version


# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
#myorigin = /etc/mailname

smtpd_banner = $myhostname ESMTP $mail_name (Ubuntu)
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# See http://www.postfix.org/COMPATIBILITY_README.html -- default to 3.6 on
# fresh installs.
compatibility_level = 3.6



# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level=may

smtp_tls_CApath=/etc/ssl/certs
smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache


smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = ip-10-100-23-50.ec2.internal
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = $myhostname, goodbanners.xyz, ip-10-100-23-50.ec2.internal, localhost.ec2.internal, localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all
virtual_alias_maps = hash:/etc/postfix/virtual
mailbox_command = /usr/bin/procmail
``````

`cat /etc/postfix/virtual`
```text
@goodbanners.xyz ubuntu
```