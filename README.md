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
cp config/env.example config/.env
vim config/.env
```
Set:

```text
EMAIL_DB_PATH=/home/ubuntu/emails.db
EMAIL_DOMAIN=yourtempemail.com
SERVER_PORT=8080
```

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `EMAIL_DOMAIN` | The domain for temporary email addresses | - | Yes |
| `EMAIL_DB_PATH` | Path to the SQLite database file | - | Yes |
| `SERVER_PORT` | Port number for the HTTP server | 8080 | No |

### Server Configuration
The server will start on the port specified by `SERVER_PORT` environment variable. If not set, it defaults to port 8080.

## API Endpoints

### Generate Temporary Email
- **URL**: `GET /generate`
- **Description**: Generates a random temporary email address
- **Response**: Plain text email address

### Get Inbox
- **URL**: `GET /inbox/{address}`
- **Description**: Retrieves emails for a specific temporary email address
- **Parameters**: `address` - The temporary email address (must end with configured EMAIL_DOMAIN)
- **Response**: JSON array of emails

### Discover Subdomains
- **URL**: `GET /subdomains/{domain}`
- **Description**: Discovers subdomains for a given domain using the subfinder tool
- **Parameters**: `domain` - The domain to search for subdomains (e.g., "example.com")
- **Response**: JSON object containing subdomain information

### Port Scanning
- **URL**: `GET /portscan/{target}`
- **Description**: Performs port scanning on a target using nmap
- **Parameters**: 
  - `target` - The target to scan (IP address, hostname, or domain)
  - `scan_type` (query param) - Type of scan: `quick`, `top`, `full`, or `custom`
  - `ports` (query param) - Custom ports for custom scan (e.g., "80,443,22,8080")
- **Response**: JSON object containing port scan results

#### Subdomain API Response Format
```json
{
  "domain": "example.com",
  "subdomains": [
    {
      "host": "www.example.com",
      "input": "example.com",
      "source": "crtsh"
    },
    {
      "host": "mail.example.com",
      "input": "example.com",
      "source": "hackertarget"
    }
  ],
  "count": 2,
  "time_seconds": 3.124
}
```

#### Port Scan API Response Format
```json
{
  "target": "example.com",
  "scan_type": "quick",
  "ports": [
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "version": "Apache httpd 2.4.41"
    },
    {
      "port": 443,
      "protocol": "tcp", 
      "state": "open",
      "service": "https",
      "version": "Apache httpd 2.4.41"
    }
  ],
  "open_ports": 2,
  "total_ports": 2,
  "scan_time_seconds": 1.23,
  "status": "completed"
}
```

#### Prerequisites
The subfinder tool must be installed on the system for this endpoint to work. Install it using:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

The nmap tool must be installed on the system for port scanning. Install it using:
```bash
# Ubuntu/Debian
sudo apt install -y nmap

# CentOS/RHEL/Fedora
sudo yum install -y nmap

# macOS
brew install nmap

# Or build from source
wget https://nmap.org/dist/nmap-7.94.tar.bz2
tar -xjf nmap-7.94.tar.bz2
cd nmap-7.94
./configure --prefix=/usr/local
make
sudo make install
```

The whois tool must be installed on the system for whois lookups. Install it using:
```bash
# Ubuntu/Debian
sudo apt install -y whois

# CentOS/RHEL/Fedora
sudo yum install -y whois

# macOS
brew install whois

# Or build from source (if not available in package manager)
# Note: whois is usually available as a package on most systems
```

The SSL scanning tools must be installed for SSL certificate analysis. Install them using:
```bash
# OpenSSL (usually pre-installed)
sudo apt install -y openssl

# Nmap with SSL scripts
sudo apt install -y nmap

# testssl.sh (comprehensive SSL testing)
git clone https://github.com/drwetter/testssl.sh.git
chmod +x testssl.sh/testssl.sh

# Verify installations
openssl version
nmap --version
./testssl.sh/testssl.sh --version
```

#### Example Usage
```bash
curl "http://localhost:8080/subdomains/pipedream.in"
```

#### Testing with Different Ports
If you've configured a different port via `SERVER_PORT`, update the URL accordingly:
```bash
# If SERVER_PORT=3000
curl "http://localhost:3000/subdomains/pipedream.in"

# If SERVER_PORT=9000  
curl "http://localhost:9000/subdomains/pipedream.in"
```

#### Error Responses
- `400 Bad Request`: Invalid domain format or missing domain parameter
- `500 Internal Server Error`: Subfinder tool not found or execution error
- `408 Request Timeout`: Subfinder command timed out

### Whois Lookup
- **URL**: `GET /whois/{domain}`
- **Description**: Performs whois lookup on a domain to get registration information
- **Parameters**: `domain` - The domain to lookup (e.g., "example.com")
- **Response**: JSON object containing whois information

#### Whois API Response Format
```json
{
  "domain": "example.com",
  "registrar": "Example Registrar, Inc.",
  "created": "2000-01-01T00:00:00Z",
  "updated": "2023-01-01T00:00:00Z",
  "expires": "2024-01-01T00:00:00Z",
  "domain_status": "clientTransferProhibited",
  "name_servers": [
    "ns1.example.com",
    "ns2.example.com"
  ],
  "raw_data": [
    {
      "field": "Registrar",
      "value": "Example Registrar, Inc."
    },
    {
      "field": "Created",
      "value": "2000-01-01T00:00:00Z"
    }
  ],
  "lookup_time_seconds": 0.85,
  "status": "completed"
}
```

#### Example Usage
```bash
# Basic whois lookup
curl "http://localhost:8080/whois/example.com"

# Lookup different TLDs
curl "http://localhost:8080/whois/google.com"
curl "http://localhost:8080/whois/github.com"
curl "http://localhost:8080/whois/mozilla.org"
```

### SSL Certificate Scanner
- **URL**: `GET /sslscan/{domain}`
- **Description**: Performs SSL certificate scanning and security analysis
- **Parameters**: 
  - `domain` - The domain to scan (e.g., "example.com")
  - `type` (query param) - Type of scan: `basic`, `quick`, or `full`
  - `port` (query param) - Port to scan (default: 443)
- **Response**: JSON object containing SSL certificate and security information

#### SSL Scan Types
- **basic** (default): Certificate info + basic security using OpenSSL and nmap
- **quick**: Fast check using Go's crypto/tls package
- **full**: Comprehensive analysis using testssl.sh for vulnerability detection

#### SSL Scanner API Response Format
```json
{
  "domain": "example.com",
  "port": 443,
  "scan_type": "basic",
  "certificate": {
    "subject": "CN=example.com",
    "issuer": "CN=DigiCert Inc, O=DigiCert Inc, C=US",
    "valid_from": "2023-01-01T00:00:00Z",
    "valid_until": "2024-01-01T00:00:00Z",
    "serial_number": "1234567890abcdef",
    "signature_algorithm": "sha256WithRSAEncryption",
    "public_key_algorithm": "rsaEncryption",
    "public_key_size": 2048
  },
  "security": {
    "tls_versions": ["TLSv1.2", "TLSv1.3"],
    "supported_ciphers": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
    "weak_ciphers": [],
    "heartbleed_vulnerable": false,
    "beast_vulnerable": false,
    "poodle_vulnerable": false,
    "certificate_transparency": true,
    "hsts_enabled": true
  },
  "vulnerabilities": [],
  "scan_time_seconds": 2.45,
  "status": "completed"
}
```

#### Example Usage
```bash
# Basic SSL scan (default)
curl "http://localhost:8080/sslscan/example.com"

# Quick SSL scan
curl "http://localhost:8080/sslscan/example.com?type=quick"

# Full SSL scan with vulnerability detection
curl "http://localhost:8080/sslscan/example.com?type=full"

# SSL scan on custom port
curl "http://localhost:8080/sslscan/example.com?port=8443"

# Different domains
curl "http://localhost:8080/sslscan/google.com?type=basic"
curl "http://localhost:8080/sslscan/github.com?type=full"
```

## MTR Traceroute API

The MTR (My TraceRoute) API provides comprehensive network path analysis with statistical information about each hop.

**Endpoint:** `GET /mtr/{target}`

**Query Parameters:**
- `mode` - Output mode: `report` (default), `raw`, or `json`
- `packets` - Number of packets to send per hop (default: 10)
- `interval` - Interval between packets in seconds (default: 1.0)
- `timeout` - Timeout for each packet in seconds (default: 2.0)
- `max_hops` - Maximum number of hops (default: 30)

**Response Format:**
```json
{
  "target": "google.com",
  "source": "192.168.1.100",
  "start_time": "2025-08-26T11:50:00Z",
  "end_time": "2025-08-26T11:50:10Z",
  "duration_seconds": 10.5,
  "total_hops": 15,
  "hops": [
    {
      "hop_number": 1,
      "host": "router.local",
      "ip": "192.168.1.1",
      "loss_percent": 0.0,
      "last_latency_ms": 1.2,
      "avg_latency_ms": 1.1,
      "best_latency_ms": 0.9,
      "worst_latency_ms": 1.5,
      "std_dev_ms": 0.2,
      "jitter_ms": 0.6
    }
  ],
  "summary": {
    "total_packets": 1500,
    "lost_packets": 15,
    "overall_loss_percent": 1.0,
    "min_latency_ms": 0.9,
    "max_latency_ms": 45.2,
    "avg_latency_ms": 12.3,
    "jitter_ms": 8.7
  }
}
```

**Examples:**
```bash
# Basic traceroute
curl "http://localhost:8080/mtr/google.com"

# Raw mode with custom parameters
curl "http://localhost:8080/mtr/google.com?mode=raw&packets=5&interval=0.5"

# JSON mode with timeout settings
curl "http://localhost:8080/mtr/cloudflare.com?mode=json&timeout=1.0&max_hops=20"
```

**Prerequisites:**
- `mtr` tool must be installed and available in PATH
- On macOS: `brew install mtr`
- On Ubuntu/Debian: `sudo apt-get install mtr`
- **Important**: MTR requires elevated privileges (sudo) to create raw sockets for network scanning
- Run the server with sudo: `sudo go run ./cmd/api` or ensure proper socket permissions

## Reverse DNS / PTR Lookup API

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
sqlite3 /home/ubuntu/emails.db <<EOF
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    temp_address TEXT,
    sender TEXT,
    subject TEXT,
    plaintext_body TEXT,
    html_body TEXT,
    expires_at TEXT,
    received_at TEXT
);

EOF

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

```bash```
sudo systemctl daemon-reload
sudo systemctl enable temp-email.service
sudo systemctl start temp-email.service
sudo systemctl restart temp-email.service
sudo systemctl status temp-email.service
``````
