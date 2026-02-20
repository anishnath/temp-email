#!/bin/bash
# setup-instance2.sh

set -e

echo "Updating system..."
apt-get update && apt-get upgrade -y

echo "Installing TeX Live..."
apt-get install -y texlive-full

echo "Installing supporting tools..."
apt-get install -y \
  ghostscript \
  imagemagick \
  pdf2svg \
  latexmk \
  build-essential \
  curl wget git \
  ufw

echo "Installing Go..."
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
source /etc/profile

echo "Creating restricted user for pdflatex..."
useradd -m -s /bin/bash latexrunner
passwd -l latexrunner

echo "Setting up temp directory..."
mkdir -p /tmp/latex-jobs
chown latexrunner:latexrunner /tmp/latex-jobs
chmod 750 /tmp/latex-jobs

echo "Configuring firewall..."
ufw default deny incoming
ufw allow ssh
ufw allow from <INSTANCE1_IP> to any port 8080
ufw --force enable

echo "Done. Verify with:"
echo "  pdflatex --version"
echo "  go version"