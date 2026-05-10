#!/usr/bin/env bash
# nowisor pilot — REST helper. Reads SN_PASS from env. Never logs password.
# Usage: ./sn-query.sh <table> <query> [fields]
set -euo pipefail
INSTANCE="${SN_INSTANCE:-https://dev265484.service-now.com}"
USER="${SN_USER:-admin}"
TABLE="${1:?table required}"
QUERY="${2:-}"
FIELDS="${3:-}"
URL="${INSTANCE}/api/now/table/${TABLE}?sysparm_query=${QUERY}"
[ -n "$FIELDS" ] && URL="${URL}&sysparm_fields=${FIELDS}"
URL="${URL}&sysparm_limit=50"
curl -sS -u "${USER}:${SN_PASS}" -H "Accept: application/json" "$URL"
