#!/bin/bash
TARGET="INSERT DVWA IP"

echo "=== 1. Nmap Port Scan ==="
nmap -sS -p 80 $TARGET

echo "=== 2. Web Fingerprint ==="
curl -v -L -A "Mozilla/5.0 (Nmap NSE)" http://$TARGET:8080/ | head -20

echo "=== 3. DVWA Directory Check ==="
curl -s http://$TARGET:8080/setup.php | grep -i dvwa
