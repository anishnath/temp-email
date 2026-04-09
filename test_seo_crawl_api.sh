#!/usr/bin/env bash
# test_seo_crawl_api.sh — start cmd/api and exercise every SEO API endpoint.
# Requires: go, curl, jq (optional but recommended). Network access to the seed URL.
#
# Endpoints tested (in order):
#   GET  /api/seo/crawls                          — crawl history (empty at start)
#   POST /api/seo/crawl                           — start main crawl
#   GET  /api/seo/crawl/{id}                      — poll until finished
#   GET  /api/seo/crawl/{id}/findings             — issue groups by severity
#   GET  /api/seo/crawl/{id}/issues/pages         — pages for first issue type
#   GET  /api/seo/crawl/{id}/page/{page_id}       — full evidence for one page
#   GET  /api/seo/crawls?url=SEED_URL             — history now shows the crawl
#   POST /api/seo/crawl (second)                  — start a new crawl to cancel
#   POST /api/seo/crawl/{id}/cancel               — abort the second crawl
#   GET  /api/seo/crawl/{id}                      — confirm crawling=false after cancel
#
# Usage:
#   ./test_seo_crawl_api.sh
# Optional env:
#   EMAIL_DOMAIN   (default: test.local)
#   SERVER_PORT    (default: 18080)
#   SEO_DB_PATH    (default: ./tmp/seo_test_crawl.sqlite)
#   SEED_URL       (default: https://8gwifi.org)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

export EMAIL_DOMAIN="${EMAIL_DOMAIN:-test.local}"
export SERVER_PORT="${SERVER_PORT:-18080}"
export SEO_CRAWL_MAX_URLS="${SEO_CRAWL_MAX_URLS:-4}"
export SEO_DB_PATH="${SEO_DB_PATH:-$ROOT/tmp/seo_test_crawl.sqlite}"
SEED_URL="${SEED_URL:-https://8gwifi.org}"

mkdir -p "$(dirname "$SEO_DB_PATH")"

echo "SEO crawl test"
echo "==============="
echo "SERVER_PORT=$SERVER_PORT SEO_CRAWL_MAX_URLS=$SEO_CRAWL_MAX_URLS"
echo "SEO_DB_PATH=$SEO_DB_PATH"
echo "SEED_URL=$SEED_URL"
echo

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi

cleanup() {
  if [[ -n "${API_PID:-}" ]] && kill -0 "$API_PID" 2>/dev/null; then
    echo
    echo "Stopping API (pid $API_PID)..."
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "Starting API (go run ./cmd/api)..."
go run ./cmd/api &
API_PID=$!

echo "Waiting for server on :${SERVER_PORT}..."
READY=0
for _ in $(seq 1 45); do
  if curl -sf "http://127.0.0.1:${SERVER_PORT}/generate" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [[ "$READY" -ne 1 ]]; then
  echo "error: server did not become ready in time" >&2
  exit 1
fi
echo "Server is up."
echo

# ── Crawl history (empty at this point) ────────────────────────────────────
echo "GET /api/seo/crawls  (history — should be empty on a fresh DB)"
if command -v jq >/dev/null 2>&1; then
  curl -sS "http://127.0.0.1:${SERVER_PORT}/api/seo/crawls" | jq .
else
  curl -sS "http://127.0.0.1:${SERVER_PORT}/api/seo/crawls"
fi
echo

# ── Main crawl ──────────────────────────────────────────────────────────────
echo "POST /api/seo/crawl"
RESP="$(curl -sS -X POST "http://127.0.0.1:${SERVER_PORT}/api/seo/crawl" \
  -H 'Content-Type: application/json' \
  -d "{\"url\":\"${SEED_URL}\"}")"

if command -v jq >/dev/null 2>&1; then
  echo "$RESP" | jq .
  CRAWL_ID="$(echo "$RESP" | jq -r '.crawl_id // empty')"
else
  echo "$RESP"
  CRAWL_ID="$(echo "$RESP" | grep -oE '"crawl_id"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+$' | head -1)"
fi

if [[ -z "$CRAWL_ID" || "$CRAWL_ID" == "null" ]]; then
  echo "error: no crawl_id in response" >&2
  exit 1
fi

echo
echo "Polling GET /api/seo/crawl/${CRAWL_ID} (crawl runs in background; may take a minute)..."
for i in $(seq 1 120); do
  ST="$(curl -sS "http://127.0.0.1:${SERVER_PORT}/api/seo/crawl/${CRAWL_ID}")"
  if command -v jq >/dev/null 2>&1; then
    echo "--- poll $i ---"
    echo "$ST" | jq .
    # Do not use (.crawling // true): jq's // treats false as missing and would return true.
    CRAWLING="$(echo "$ST" | jq -r 'if .crawling == null then "true" else (.crawling | tostring) end')"
  else
    echo "$ST"
    CRAWLING="true"
  fi
  if [[ "$CRAWLING" == "false" ]]; then
    echo "Crawl finished (crawling=false)."
    break
  fi
  sleep 2
done

echo
echo "GET /api/seo/crawl/${CRAWL_ID}/findings (issue types × page counts)"
FINDINGS="$(curl -sS "http://127.0.0.1:${SERVER_PORT}/api/seo/crawl/${CRAWL_ID}/findings")"
if command -v jq >/dev/null 2>&1; then
  echo "$FINDINGS" | jq .

  # Pick the first available issue type across all severities
  FIRST_TYPE="$(echo "$FINDINGS" | jq -r '.warning[0].error_type // .alert[0].error_type // .critical[0].error_type // empty')"

  if [[ -n "$FIRST_TYPE" ]]; then
    echo
    echo "GET /api/seo/crawl/${CRAWL_ID}/issues/pages?type=${FIRST_TYPE}&limit=5"
    PAGES_RESP="$(curl -sS "http://127.0.0.1:${SERVER_PORT}/api/seo/crawl/${CRAWL_ID}/issues/pages?type=${FIRST_TYPE}&limit=5")"
    echo "$PAGES_RESP" | jq .

    # Pick the first page_id from the list and fetch its full evidence payload
    FIRST_PAGE_ID="$(echo "$PAGES_RESP" | jq -r '.pages[0].id // empty')"
    if [[ -n "$FIRST_PAGE_ID" && "$FIRST_PAGE_ID" != "null" ]]; then
      echo
      echo "GET /api/seo/crawl/${CRAWL_ID}/page/${FIRST_PAGE_ID}  (full evidence for one page)"
      curl -sS "http://127.0.0.1:${SERVER_PORT}/api/seo/crawl/${CRAWL_ID}/page/${FIRST_PAGE_ID}" | jq .
    fi
  fi
else
  echo "$FINDINGS"
fi

# ── Crawl history (should now list the finished crawl) ─────────────────────
echo
echo "GET /api/seo/crawls?url=${SEED_URL}  (history — should show 1 crawl)"
if command -v jq >/dev/null 2>&1; then
  curl -sS "http://127.0.0.1:${SERVER_PORT}/api/seo/crawls?url=${SEED_URL}" | jq .
else
  curl -sS "http://127.0.0.1:${SERVER_PORT}/api/seo/crawls?url=${SEED_URL}"
fi

# ── Cancel test: start a second crawl then immediately cancel it ────────────
echo
echo "POST /api/seo/crawl  (second crawl — will be cancelled)"
RESP2="$(curl -sS -X POST "http://127.0.0.1:${SERVER_PORT}/api/seo/crawl" \
  -H 'Content-Type: application/json' \
  -d "{\"url\":\"${SEED_URL}\"}")"
if command -v jq >/dev/null 2>&1; then
  echo "$RESP2" | jq .
  CRAWL_ID2="$(echo "$RESP2" | jq -r '.crawl_id // empty')"
else
  echo "$RESP2"
  CRAWL_ID2="$(echo "$RESP2" | grep -oE '"crawl_id"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+$' | head -1)"
fi

if [[ -n "$CRAWL_ID2" && "$CRAWL_ID2" != "null" ]]; then
  # Give the crawler a moment to start fetching
  sleep 2
  echo
  echo "POST /api/seo/crawl/${CRAWL_ID2}/cancel"
  if command -v jq >/dev/null 2>&1; then
    curl -sS -X POST "http://127.0.0.1:${SERVER_PORT}/api/seo/crawl/${CRAWL_ID2}/cancel" | jq .
  else
    curl -sS -X POST "http://127.0.0.1:${SERVER_PORT}/api/seo/crawl/${CRAWL_ID2}/cancel"
  fi

  # Poll until the cancel takes effect (crawling should become false quickly)
  echo
  echo "Verifying cancel — polling GET /api/seo/crawl/${CRAWL_ID2}..."
  for i in $(seq 1 15); do
    ST2="$(curl -sS "http://127.0.0.1:${SERVER_PORT}/api/seo/crawl/${CRAWL_ID2}")"
    if command -v jq >/dev/null 2>&1; then
      CRAWLING2="$(echo "$ST2" | jq -r 'if .crawling == null then "true" else (.crawling | tostring) end')"
    else
      CRAWLING2="true"
    fi
    if [[ "$CRAWLING2" == "false" ]]; then
      echo "Confirmed: crawl ${CRAWL_ID2} is stopped (crawling=false)."
      if command -v jq >/dev/null 2>&1; then
        echo "$ST2" | jq '{crawl_id,crawling,total_urls,total_issues}'
      fi
      break
    fi
    sleep 1
  done
fi

echo
echo "Done."
