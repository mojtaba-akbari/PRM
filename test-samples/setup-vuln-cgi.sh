#!/bin/bash

# Compile vulnerable CGI (disable all protections)
gcc -o vuln-cgi vuln-cgi.c -fno-stack-protector -z execstack -no-pie -g

# Setup CGI directory
mkdir -p /var/www/cgi-bin
cp vuln-cgi /var/www/cgi-bin/
chmod +x /var/www/cgi-bin/vuln-cgi

# Install fcgiwrap if needed
if ! command -v fcgiwrap &> /dev/null; then
    echo "Installing fcgiwrap..."
    dnf install -y fcgiwrap spawn-fcgi
fi

# Start fcgiwrap
spawn-fcgi -s /var/run/fcgiwrap.socket -U nginx -G nginx /usr/sbin/fcgiwrap

# Copy nginx config
cp nginx-vuln.conf /etc/nginx/conf.d/

# Restart nginx
systemctl restart nginx

echo "Vulnerable CGI deployed at http://localhost:8080/vuln"
echo "Test: curl 'http://localhost:8080/vuln?test=hello'"
echo ""
echo "Get exploit address:"
nm /var/www/cgi-bin/vuln-cgi | grep execute_command
echo ""
echo "Run exploit: ./exploit.py <address>"
