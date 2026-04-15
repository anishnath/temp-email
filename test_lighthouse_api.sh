#!/usr/bin/env bash
# test_lighthouse_api.sh — start cmd/api and exercise every Lighthouse endpoint.
# Requires: go, curl, jq (optional but recommended).
# Lighthouse + Chrome must be installed (npm install -g lighthouse).
#
# Endpoints tested (in order):
#   GET  /api/lighthouse/audits              — history (empty on fresh DB)
#   POST /api/lighthouse                     — run audit, get audit_id
#   GET  /api/lighthouse/audits/{id}         — retrieve stored result by audit_id
#   GET  /api/lighthouse/audits?url=URL      — history now shows 1 entry
#   POST /api/lighthouse (desktop)           — second audit, different strategy
#   GET  /api/lighthouse/audits              — history shows 2 entries
#
# Usage:
#   ./test_lighthouse_api.sh
# Optional env:
#   EMAIL_DOMAIN          (default: test.local)
#   SERVER_PORT           (default: 18080)
#   LIGHTHOUSE_DB_PATH    (default: ./tmp/lh_test.sqlite)
#   LIGHTHOUSE_CMD        (default: lighthouse — override for NVM installs)
#   TEST_URL              (default: https://airhorner.com/)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

export EMAIL_DOMAIN="${EMAIL_DOMAIN:-test.local}"
export SERVER_PORT="${SERVER_PORT:-18080}"
export LIGHTHOUSE_DB_PATH="${LIGHTHOUSE_DB_PATH:-$ROOT/tmp/lh_test.sqlite}"
# Resolve NVM lighthouse automatically if not already set
if [[ -z "${LIGHTHOUSE_CMD:-}" ]]; then
  if command -v lighthouse >/dev/null 2>&1; then
    export LIGHTHOUSE_CMD="$(command -v lighthouse)"
  fi
fi
TEST_URL="${TEST_URL:-https://airhorner.com/}"

mkdir -p "$(dirname "$LIGHTHOUSE_DB_PATH")"

BASE="http://127.0.0.1:${SERVER_PORT}"

echo "Lighthouse API test"
echo "==================="
echo "SERVER_PORT=$SERVER_PORT"
echo "LIGHTHOUSE_DB_PATH=$LIGHTHOUSE_DB_PATH"
echo "LIGHTHOUSE_CMD=${LIGHTHOUSE_CMD:-lighthouse}"
echo "TEST_URL=$TEST_URL"
echo

# ── helpers ──────────────────────────────────────────────────────────────────
check_status() {
  local label="$1" expected="$2" actual="$3" body="$4"
  if [[ "$actual" -ne "$expected" ]]; then
    echo "FAIL [$label]: expected HTTP $expected, got $actual"
    echo "Body: $body"
    exit 1
  fi
  echo "OK   [$label]: HTTP $actual"
}

jq_or_echo() {
  if command -v jq >/dev/null 2>&1; then
    echo "$1" | jq .
  else
    echo "$1"
  fi
}

jq_field() {
  # $1=json  $2=field  $3=default
  if command -v jq >/dev/null 2>&1; then
    echo "$1" | jq -r "${2} // \"${3:-}\""
  else
    echo "${3:-}"
  fi
}

# ── curl helpers ─────────────────────────────────────────────────────────────
api_get() {
  curl -sS -w '\n%{http_code}' "$BASE$1"
}

api_post() {
  curl -sS -w '\n%{http_code}' -X POST "$BASE$1" \
    -H 'Content-Type: application/json' \
    -d "$2"
}

split_body_code() {
  # last line = status code, rest = body  (macOS-safe: sed '$d' instead of head -n -1)
  BODY="$(echo "$1" | sed '$d')"
  CODE="$(echo "$1" | tail -n 1)"
}

# ── start server ─────────────────────────────────────────────────────────────
if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2; exit 1
fi

API_PID=""
SERVER_STARTED=0

cleanup() {
  if [[ "$SERVER_STARTED" -eq 1 && -n "${API_PID:-}" ]] && kill -0 "$API_PID" 2>/dev/null; then
    echo; echo "Stopping API (pid $API_PID)..."
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Reuse an already-running server; only start a new one if nothing is listening.
if curl -sf "$BASE/generate" >/dev/null 2>&1; then
  echo "Server already running on :${SERVER_PORT} — reusing it."
else
  echo "Starting API (go run ./cmd/api)..."
  go run ./cmd/api &
  API_PID=$!
  SERVER_STARTED=1

  echo "Waiting for server on :${SERVER_PORT}..."
  READY=0
  for _ in $(seq 1 45); do
    if curl -sf "$BASE/generate" >/dev/null 2>&1; then READY=1; break; fi
    sleep 1
  done
  [[ "$READY" -eq 1 ]] || { echo "error: server did not become ready" >&2; exit 1; }
  echo "Server is up."
fi
echo

# ── 1. Empty history ──────────────────────────────────────────────────────────
echo "── 1. GET /api/lighthouse/audits  (empty history)"
RAW="$(api_get /api/lighthouse/audits)"
split_body_code "$RAW"
check_status "empty history" 200 "$CODE" "$BODY"
jq_or_echo "$BODY"
echo

# ── 2. Run first audit (mobile) ───────────────────────────────────────────────
echo "── 2. POST /api/lighthouse  (mobile audit — takes 30–90 s)"
RAW="$(api_post /api/lighthouse "{\"url\":\"${TEST_URL}\",\"strategy\":\"mobile\"}")"
split_body_code "$RAW"
check_status "POST mobile audit" 200 "$CODE" "$BODY"
jq_or_echo "$BODY"

AUDIT_ID="$(jq_field "$BODY" '.audit_id' '')"
PERF="$(jq_field    "$BODY" '.scores.performance' 'n/a')"
SEO="$(jq_field     "$BODY" '.scores.seo' 'n/a')"
A11Y="$(jq_field    "$BODY" '.scores.accessibility' 'n/a')"
BP="$(jq_field      "$BODY" '.scores.best_practices' 'n/a')"
echo
echo "  audit_id=$AUDIT_ID  performance=$PERF  seo=$SEO  accessibility=$A11Y  best_practices=$BP"

if [[ -z "$AUDIT_ID" || "$AUDIT_ID" == "null" || "$AUDIT_ID" == "0" ]]; then
  echo "FAIL: no audit_id in POST response" >&2; exit 1
fi
echo

# ── 3. Retrieve audit by ID ───────────────────────────────────────────────────
echo "── 3. GET /api/lighthouse/audits/${AUDIT_ID}  (full stored result)"
RAW="$(api_get "/api/lighthouse/audits/${AUDIT_ID}")"
split_body_code "$RAW"
check_status "get audit by id" 200 "$CODE" "$BODY"
jq_or_echo "$BODY"
echo

# ── 4. History now has 1 entry ────────────────────────────────────────────────
echo "── 4. GET /api/lighthouse/audits?url=${TEST_URL}  (should show 1 entry)"
RAW="$(api_get "/api/lighthouse/audits?url=${TEST_URL}")"
split_body_code "$RAW"
check_status "history url filter" 200 "$CODE" "$BODY"
jq_or_echo "$BODY"
COUNT="$(jq_field "$BODY" '.count' '0')"
if [[ "$COUNT" -lt 1 ]]; then
  echo "FAIL: expected at least 1 audit in history, got count=$COUNT" >&2; exit 1
fi
echo "  count=$COUNT  ✓"
echo

# ── 5. Second audit (desktop, performance+seo only) ───────────────────────────
echo "── 5. POST /api/lighthouse  (desktop, categories=performance,seo)"
RAW="$(api_post /api/lighthouse \
  "{\"url\":\"${TEST_URL}\",\"strategy\":\"desktop\",\"categories\":[\"performance\",\"seo\"]}")"
split_body_code "$RAW"
check_status "POST desktop audit" 200 "$CODE" "$BODY"
jq_or_echo "$BODY"
AUDIT_ID2="$(jq_field "$BODY" '.audit_id' '')"
echo "  audit_id=$AUDIT_ID2"
echo

# ── 6. History now has 2 entries ──────────────────────────────────────────────
echo "── 6. GET /api/lighthouse/audits?url=${TEST_URL}  (should show 2 entries)"
RAW="$(api_get "/api/lighthouse/audits?url=${TEST_URL}")"
split_body_code "$RAW"
check_status "history 2 entries" 200 "$CODE" "$BODY"
jq_or_echo "$BODY"
COUNT2="$(jq_field "$BODY" '.count' '0')"
if [[ "$COUNT2" -lt 2 ]]; then
  echo "FAIL: expected at least 2 audits, got count=$COUNT2" >&2; exit 1
fi
echo "  count=$COUNT2  ✓"
echo

# ── 7. Error cases ────────────────────────────────────────────────────────────
echo "── 7a. POST /api/lighthouse  (missing url → 400)"
RAW="$(api_post /api/lighthouse '{\"strategy\":\"mobile\"}')"
split_body_code "$RAW"
check_status "missing url" 400 "$CODE" "$BODY"

echo "── 7b. GET /api/lighthouse/audits/99999  (unknown id → 404)"
RAW="$(api_get /api/lighthouse/audits/99999)"
split_body_code "$RAW"
check_status "unknown audit id" 404 "$CODE" "$BODY"

echo "── 7c. GET /api/lighthouse/audits/abc  (invalid id → 400)"
RAW="$(api_get /api/lighthouse/audits/abc)"
split_body_code "$RAW"
check_status "invalid audit id" 400 "$CODE" "$BODY"
echo

echo "All Lighthouse API tests passed."
