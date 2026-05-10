#!/usr/bin/env bash
# nowisor v0.2 — post-install suite bootstrap
#
# The Fluent SDK (v4.6.0) does not expose a ScanCheckSuite API, so the suite
# and its m2m membership rows cannot ship inside the application. Instance
# Scan checks that are not in any active suite never execute, even when the
# checks themselves are active=true. This script creates the suite and links
# the 3 nowisor checks via the standard /api/now/table/ REST endpoints.
#
# Run once after `now-sdk install`. Idempotent: safe to re-run; will only
# create missing rows. Re-run after every `now-sdk install --reinstall`
# because the m2m rows are cascade-deleted when the application is uninstalled.
#
# Usage:
#   SN_INSTANCE=https://yourinstance.service-now.com \
#   SN_USER=admin \
#   SN_PASS=... \
#   ./scripts/create-suite.sh
#
# Reads from env (no disk persistence of credentials).
set -euo pipefail

INSTANCE="${SN_INSTANCE:-https://dev265484.service-now.com}"
USER="${SN_USER:-admin}"
: "${SN_PASS:?SN_PASS env var required}"

SCOPE_ID='2159d2d168744fc18f5a27536d212f88'  # x_nowisor_isp scope sys_id
SUITE_NAME='nowisor Instance Scan Pack'

# Deterministic check sys_ids (Fluent SDK $id-derived; stable across reinstalls)
CHECK_IDS=(
  'b20ecfa9500e4ac48fcab135b839b352'  # CSRF Token Enforcement
  'b6d3e0840f21424e908a542597b07387'  # eval() Usage Detector
  'e27b5266082240d8bf97d231ca14ca52'  # Admin Role Concentration
)

curl_do() {
  curl -fsS -u "${USER}:${SN_PASS}" -H 'Accept: application/json' "$@"
}

# 1. Find or create the suite
SUITE_ID=$(curl_do "${INSTANCE}/api/now/table/scan_check_suite?sysparm_query=name=${SUITE_NAME// /%20}&sysparm_fields=sys_id&sysparm_limit=1" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(r[0]["sys_id"] if r else "")')

if [ -z "$SUITE_ID" ]; then
  SUITE_ID=$(curl_do -H 'Content-Type: application/json' \
    -X POST "${INSTANCE}/api/now/table/scan_check_suite" \
    -d "{\"name\":\"${SUITE_NAME}\",\"active\":\"true\",\"description\":\"nowisor Instance Scan Pack — created by post-install bootstrap. SDK does not expose a ScanCheckSuite API, so the suite is provisioned via REST.\"}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["sys_id"])')
  echo "Created suite: ${SUITE_ID}"
else
  echo "Suite already exists: ${SUITE_ID}"
fi

# 2. For each check, ensure m2m row exists
for CHECK_ID in "${CHECK_IDS[@]}"; do
  EXISTING=$(curl_do "${INSTANCE}/api/now/table/scan_check_suite_check?sysparm_query=suite=${SUITE_ID}^check=${CHECK_ID}&sysparm_fields=sys_id&sysparm_limit=1" \
    | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(r[0]["sys_id"] if r else "")')
  if [ -z "$EXISTING" ]; then
    curl_do -H 'Content-Type: application/json' \
      -X POST "${INSTANCE}/api/now/table/scan_check_suite_check" \
      -d "{\"check\":\"${CHECK_ID}\",\"suite\":\"${SUITE_ID}\",\"score_weight\":\"1\"}" >/dev/null
    echo "  linked check ${CHECK_ID} to suite"
  else
    echo "  check ${CHECK_ID} already in suite"
  fi
done

echo ""
echo "Done. To trigger a scan:"
echo "  curl -u ${USER}:\$SN_PASS -H 'Accept: application/json' \\"
echo "    -X POST '${INSTANCE}/api/sn_cicd/instance_scan/full_scan'"
echo ""
echo "Or run only the nowisor suite via UI: navigate to scan_check_suite"
echo "list view, open '${SUITE_NAME}', click 'Execute Suite Scan'."
