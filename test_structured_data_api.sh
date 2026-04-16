#!/usr/bin/env bash
# test_structured_data_api.sh — end-to-end tests for POST /api/structured-data/extract
set -euo pipefail

SERVER_PORT="${SERVER_PORT:-7080}"
BASE_URL="http://localhost:${SERVER_PORT}"
PASS=0
FAIL=0

# ── Helpers ───────────────────────────────────────────────────────────────────

green() { echo -e "\033[32m✓ $*\033[0m"; }
red()   { echo -e "\033[31m✗ $*\033[0m"; }

check() {
  local label="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    green "$label"
    PASS=$((PASS+1))
  else
    red "$label (want=$want, got=$got)"
    FAIL=$((FAIL+1))
  fi
}

check_ge() {
  local label="$1" got="$2" min="$3"
  if [ "$got" -ge "$min" ] 2>/dev/null; then
    green "$label (${got} >= ${min})"
    PASS=$((PASS+1))
  else
    red "$label (want >= ${min}, got=${got})"
    FAIL=$((FAIL+1))
  fi
}

check_http() {
  local label="$1" got="$2" want="$3"
  check "$label [HTTP $want]" "$got" "$want"
}

api_post() {
  local path="$1" body="$2"
  curl -s -o /tmp/sd_body.json -w "%{http_code}" \
    -X POST "${BASE_URL}${path}" \
    -H 'Content-Type: application/json' \
    -d "$body"
}

body() { cat /tmp/sd_body.json; }
jf()   { body | jq -r "$1" 2>/dev/null || echo ""; }

# ── Server check ──────────────────────────────────────────────────────────────

echo ""
echo "=== Structured Data Extract API ==="
echo "Server: ${BASE_URL}"
echo ""

if ! curl -s --connect-timeout 3 "${BASE_URL}/" -o /dev/null 2>/dev/null; then
  echo "Server not running on port ${SERVER_PORT}. Start with: go run ./cmd/api"
  exit 1
fi

# ── Error cases ───────────────────────────────────────────────────────────────

echo "--- Error handling ---"

code=$(api_post /api/structured-data/extract 'not-json')
check_http "invalid JSON → 400" "$code" "400"

code=$(api_post /api/structured-data/extract '{}')
check_http "missing url → 400" "$code" "400"

code=$(api_post /api/structured-data/extract '{"url":""}')
check_http "empty url → 400" "$code" "400"

code=$(api_post /api/structured-data/extract '{"url":"https://this-domain-does-not-exist-xyz-abc.com/"}')
check_http "unreachable URL → 422" "$code" "422"

# ── Real page: airhorner.com ──────────────────────────────────────────────────

echo ""
echo "--- Real page: https://airhorner.com/ ---"

code=$(api_post /api/structured-data/extract '{"url":"https://airhorner.com/"}')
check_http "fetch airhorner.com → 200" "$code" "200"

url=$(jf '.url')
check "url echoed back" "$url" "https://airhorner.com/"

fetched_at=$(jf '.fetched_at')
check "fetched_at present" "$([ -n "$fetched_at" ] && echo ok || echo "")" "ok"

jsonld_type=$(jf '.jsonld | type')
check "jsonld is array" "$jsonld_type" "array"

microdata_type=$(jf '.microdata | type')
check "microdata is array" "$microdata_type" "array"

rdfa_type=$(jf '.rdfa | type')
check "rdfa is array" "$rdfa_type" "array"

metatags_type=$(jf '.metatags | type')
check "metatags is object" "$metatags_type" "object"

# ── Rich structured data page: schema.org ─────────────────────────────────────

echo ""
echo "--- Rich page: https://schema.org/Article ---"

code=$(api_post /api/structured-data/extract '{"url":"https://schema.org/Article"}')
check_http "fetch schema.org/Article → 200" "$code" "200"

jsonld_count=$(jf '.jsonld | length')
check_ge "jsonld items >= 1" "$jsonld_count" "1"

# schema.org uses @graph — verify it is flattened into individual items
# After flattening, each item should have @context and @type (no @graph wrapper)
first_context=$(jf '.jsonld[0]["@context"] // ""')
check "@graph flattened: first item has @context" "$([ -n "$first_context" ] && echo ok || echo "")" "ok"

has_graph_wrapper=$(jf '.jsonld[] | select(has("@graph")) | "@graph found"' | head -1)
check "@graph wrapper removed after flattening" "$has_graph_wrapper" ""

metatags_count=$(jf '.metatags | length')
check_ge "metatags >= 1" "$metatags_count" "1"

# ── Page with Open Graph / Twitter cards ──────────────────────────────────────

echo ""
echo "--- Social meta tags: https://github.com ---"

code=$(api_post /api/structured-data/extract '{"url":"https://github.com"}')
check_http "fetch github.com → 200" "$code" "200"

og_title=$(jf '.metatags["og:title"] // ""')
check "og:title present" "$([ -n "$og_title" ] && echo ok || echo "")" "ok"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=================================="
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "=================================="

[ "$FAIL" -eq 0 ]
