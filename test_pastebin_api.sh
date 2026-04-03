#!/bin/bash

# Test script for the Pastebin API endpoints
# Requires: server running on localhost:8080 with pastebin configured
# Usage: ./test_pastebin_api.sh [base_url]

BASE_URL="${1:-http://localhost:8080}"
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

echo "Testing Pastebin API Endpoint"
echo "============================="
echo "Base URL: $BASE_URL"
echo ""

# Helper: show JSON response
show() {
  echo "$1" | jq '.' 2>/dev/null || echo "$1"
}

# 1. Health check
echo "1. Health check GET /api/pastebin/health:"
RESP=$(curl -s "$BASE_URL/api/pastebin/health")
show "$RESP"
if echo "$RESP" | jq -e '.status == "ok"' &>/dev/null; then
  echo "   -> OK"
else
  echo "   -> Pastebin may not be configured (503 expected if R2 not set up)"
fi

echo -e "\n"

# 2. Stats
echo "2. Stats GET /api/pastebin/stats:"
STATS_RESP=$(curl -s "$BASE_URL/api/pastebin/stats")
show "$STATS_RESP"
echo ""

# 2b. Recent pastes (no auth)
echo "2b. Recent pastes GET /api/pastebin/recent:"
RECENT_RESP=$(curl -s "$BASE_URL/api/pastebin/recent")
show "$RECENT_RESP"
echo ""

# 3. Create API key
echo "3. Create API key POST /api/pastebin/keys:"
KEY_RESP=$(curl -s -X POST "$BASE_URL/api/pastebin/keys")
show "$KEY_RESP"
API_KEY=$(echo "$KEY_RESP" | jq -r '.apiKey // empty')
KEY_ID=$(echo "$KEY_RESP" | jq -r '.keyID // empty')
if [[ -n "$API_KEY" ]]; then
  echo "   -> API key created"
else
  echo "   -> May return 503 if pastebin not configured"
fi

echo -e "\n"

# 4. Create text paste (JSON)
echo "4. Create text paste POST /api/pastebin (JSON):"
CREATE_RESP=$(curl -s -X POST "$BASE_URL/api/pastebin" \
  -H "Content-Type: application/json" \
  -d '{"content":"Hello from test script","title":"Test Paste","syntax":"plain","expiry":"24h"}' \
  -c "$COOKIE_JAR" -b "$COOKIE_JAR")
show "$CREATE_RESP"
PASTE_ID=$(echo "$CREATE_RESP" | jq -r '.id // empty')
DELETE_TOKEN=$(echo "$CREATE_RESP" | jq -r '.deleteToken // empty')
if [[ -n "$PASTE_ID" ]]; then
  echo "   -> Created paste ID: $PASTE_ID"
else
  echo "   -> Create failed (pastebin may not be configured)"
fi

echo -e "\n"

# 5. Get paste by ID
if [[ -n "$PASTE_ID" ]]; then
  echo "5. Get paste GET /api/pastebin/$PASTE_ID:"
  GET_RESP=$(curl -s "$BASE_URL/api/pastebin/$PASTE_ID")
  show "$GET_RESP"
  echo ""

  # 6. Get raw content
  echo "6. Get raw GET /api/pastebin/$PASTE_ID/raw:"
  RAW=$(curl -s "$BASE_URL/api/pastebin/$PASTE_ID/raw")
  echo "   Content: $RAW"
  echo ""
fi

# 6b. File upload (multipart)
echo "6b. Create file paste POST /api/pastebin (multipart):"
FILE_TMP=$(mktemp)
echo "file content for upload test" > "$FILE_TMP"
trap "rm -f $COOKIE_JAR $FILE_TMP" EXIT
FILE_RESP=$(curl -s -X POST "$BASE_URL/api/pastebin" \
  -F "file=@$FILE_TMP" \
  -F "title=Uploaded File" \
  -F "expiry=24h" \
  -c "$COOKIE_JAR" -b "$COOKIE_JAR")
show "$FILE_RESP"
FILE_ID=$(echo "$FILE_RESP" | jq -r '.id // empty')
FILE_DEL_TOKEN=$(echo "$FILE_RESP" | jq -r '.deleteToken // empty')
if [[ -n "$FILE_ID" ]]; then
  echo "   -> Created file paste ID: $FILE_ID"
  echo "   Raw content: $(curl -s "$BASE_URL/api/pastebin/$FILE_ID/raw")"
else
  echo "   -> Create failed or pastebin not configured"
fi
trap "rm -f $COOKIE_JAR $FILE_TMP" EXIT
echo ""

# 7. Create paste with API key (if we have one)
if [[ -n "$API_KEY" ]]; then
  echo "7. Create paste with X-API-Key:"
  CREATE_KEY_RESP=$(curl -s -X POST "$BASE_URL/api/pastebin" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d '{"content":"Paste via API key","title":"API Key Test","expiry":"1h"}')
  show "$CREATE_KEY_RESP"
  echo ""

  # 8. List mine with API key
  echo "8. List mine GET /api/pastebin/mine (with X-API-Key):"
  MINE_RESP=$(curl -s "$BASE_URL/api/pastebin/mine" -H "X-API-Key: $API_KEY")
  show "$MINE_RESP"
  echo ""
fi

# 9. List mine with session cookie
echo "9. List mine GET /api/pastebin/mine (with session cookie):"
MINE_SESSION=$(curl -s "$BASE_URL/api/pastebin/mine" -b "$COOKIE_JAR")
show "$MINE_SESSION"
echo ""

# 10. Delete paste (X-Delete-Token header)
if [[ -n "$PASTE_ID" && -n "$DELETE_TOKEN" ]]; then
  echo "10. Delete paste DELETE /api/pastebin/$PASTE_ID (X-Delete-Token):"
  DELETE_RESP=$(curl -s -w "\n%{http_code}" -X DELETE "$BASE_URL/api/pastebin/$PASTE_ID" \
    -H "X-Delete-Token: $DELETE_TOKEN")
  CODE=$(echo "$DELETE_RESP" | tail -n1)
  BODY=$(echo "$DELETE_RESP" | sed '$d')
  echo "   HTTP $CODE"
  if [[ "$CODE" == "204" ]]; then
    echo "   -> Deleted successfully"
  fi
  echo ""

  # 11. Verify deleted (should 404)
  echo "11. Get deleted paste (expect 404):"
  NOT_FOUND=$(curl -s -w "\n%{http_code}" "$BASE_URL/api/pastebin/$PASTE_ID")
  CODE=$(echo "$NOT_FOUND" | tail -n1)
  BODY=$(echo "$NOT_FOUND" | sed '$d')
  show "$BODY"
  echo "   HTTP $CODE"
fi

# 10b. Delete via query param (use file paste if we have one)
if [[ -n "$FILE_ID" && -n "$FILE_DEL_TOKEN" ]]; then
  echo -e "\n10b. Delete via query param DELETE /api/pastebin/$FILE_ID?deleteToken=...:"
  DEL_Q=$(curl -s -w "\n%{http_code}" -X DELETE "$BASE_URL/api/pastebin/$FILE_ID?deleteToken=$FILE_DEL_TOKEN")
  echo "   HTTP $(echo "$DEL_Q" | tail -n1)"
fi

# 12. Burn-after-read (paste deleted after first view; second get returns 404)
echo -e "\n12. Burn-after-read: create, get once (200), get again (404 - paste deleted):"
BURN_RESP=$(curl -s -X POST "$BASE_URL/api/pastebin" \
  -H "Content-Type: application/json" \
  -d '{"content":"Burn me","title":"Burn Test","burnAfterRead":true,"expiry":"24h"}')
BURN_ID=$(echo "$BURN_RESP" | jq -r '.id // empty')
if [[ -n "$BURN_ID" ]]; then
  BURN_FIRST=$(curl -s -w "\n%{http_code}" "$BASE_URL/api/pastebin/$BURN_ID")
  echo "   First GET: HTTP $(echo "$BURN_FIRST" | tail -n1)"
  BURN_SECOND=$(curl -s -w "\n%{http_code}" "$BASE_URL/api/pastebin/$BURN_ID")
  BURN_CODE=$(echo "$BURN_SECOND" | tail -n1)
  echo "   Second GET (expect 404): HTTP $BURN_CODE"
  if [[ "$BURN_CODE" == "404" ]]; then
    echo "   -> Burn-after-read OK (paste deleted after first view)"
  fi
else
  echo "   -> Create failed, skip burn test"
fi

# 13. Private paste with passphrase
echo -e "\n13. Private paste: without passphrase (403), wrong passphrase (403), correct (200):"
PRIV_RESP=$(curl -s -X POST "$BASE_URL/api/pastebin" \
  -H "Content-Type: application/json" \
  -d '{"content":"Secret data","title":"Private","visibility":"private","passphrase":"mypass123","expiry":"24h"}')
PRIV_ID=$(echo "$PRIV_RESP" | jq -r '.id // empty')
if [[ -n "$PRIV_ID" ]]; then
  echo "   Created: $PRIV_ID"
  NO_PASS=$(curl -s -w "\n%{http_code}" "$BASE_URL/api/pastebin/$PRIV_ID")
  echo "   Without passphrase: HTTP $(echo "$NO_PASS" | tail -n1)"
  WRONG_PASS=$(curl -s -w "\n%{http_code}" "$BASE_URL/api/pastebin/$PRIV_ID?passphrase=wrong")
  echo "   Wrong passphrase: HTTP $(echo "$WRONG_PASS" | tail -n1)"
  RIGHT_PASS=$(curl -s -w "\n%{http_code}" "$BASE_URL/api/pastebin/$PRIV_ID?passphrase=mypass123")
  echo "   Correct passphrase: HTTP $(echo "$RIGHT_PASS" | tail -n1)"
  RIGHT_BODY=$(echo "$RIGHT_PASS" | sed '$d')
  if echo "$RIGHT_BODY" | jq -e '.content == "Secret data"' &>/dev/null; then
    echo "   -> Content decrypted correctly"
  fi
else
  echo "   -> Create failed, skip private test"
fi

# 14. View count
echo -e "\n14. View count: create paste, get twice, verify viewCount increments:"
VIEW_RESP=$(curl -s -X POST "$BASE_URL/api/pastebin" \
    -H "Content-Type: application/json" \
    -d '{"content":"View count test","title":"ViewTest","expiry":"24h"}')
VIEW_ID=$(echo "$VIEW_RESP" | jq -r '.id // empty')
if [[ -n "$VIEW_ID" ]]; then
  G1=$(curl -s "$BASE_URL/api/pastebin/$VIEW_ID" | jq -r '.viewCount // 0')
  G2=$(curl -s "$BASE_URL/api/pastebin/$VIEW_ID" | jq -r '.viewCount // 0')
  echo "   After 1st get: viewCount=$G1, after 2nd: viewCount=$G2"
  if [[ "$G2" -gt "$G1" ]]; then
    echo "   -> View count incremented"
  fi
else
  echo "   -> Create failed, skip view count test"
fi

# 15. Custom slug (8+ chars required, use random to avoid conflicts)
SLUG_RAND="slug$(date +%s)99"
echo -e "\n15. Custom slug: create with slug '$SLUG_RAND', verify id matches:"
SLUG_RESP=$(curl -s -X POST "$BASE_URL/api/pastebin" \
  -H "Content-Type: application/json" \
  -d "{\"content\":\"Slug test\",\"title\":\"Slug\",\"slug\":\"$SLUG_RAND\",\"expiry\":\"24h\"}")
SLUG_ID=$(echo "$SLUG_RESP" | jq -r '.id // empty')
if [[ -n "$SLUG_ID" ]]; then
  echo "   Created with slug: id=$SLUG_ID"
  if [[ "$SLUG_ID" == "$SLUG_RAND" ]]; then
    echo "   -> Custom slug OK"
  else
    echo "   -> Note: id differs (slug may have been taken)"
  fi
else
  echo "   Response: $(echo "$SLUG_RESP" | jq -c '.')"
  echo "   -> Create failed (may be SLUG_TAKEN if slug exists)"
fi

# 16. Error: paste not found
echo -e "\n16. Get non-existent paste (expect 404):"
NF_RESP=$(curl -s "$BASE_URL/api/pastebin/nonexistent12345")
show "$NF_RESP"

echo -e "\n\nTest completed!"
