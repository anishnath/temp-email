#!/bin/bash
source /home/ubuntu/temp-email/config/.env
cd /home/ubuntu/temp-email
go build -o bin/temp-email ./cmd/api
go build -o bin/process-email ./cmd/email-processor
go build -o bin/dummy-data ./cmd/dummy-data
sudo mv bin/process-email /usr/local/bin/
sudo cp config/postfix/* /etc/postfix/
sudo postmap /etc/postfix/virtual
sudo cp config/procmailrc /home/ubuntu/.procmailrc
./bin/temp-email &