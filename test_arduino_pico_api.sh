#!/bin/bash
# Quick integration test: POST /api/arduino-compile for Raspberry Pi Pico (rp2040:rp2040:rpipico).
# Expects success + outputFormat "uf2" when the server uses an image with rp2040:rp2040 (see docker/arduino-compile/Dockerfile).
#
# Usage: ./test_arduino_pico_api.sh [base_url]
# Example: ./test_arduino_pico_api.sh http://localhost:8080

set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"
ENDPOINT="${BASE_URL}/api/arduino-compile"

SKETCH='void setup() {
  pinMode(25, OUTPUT);
}
void loop() {
  digitalWrite(25, HIGH);
  delay(500);
  digitalWrite(25, LOW);
  delay(500);
}'

echo "Pico compile test -> $ENDPOINT"
echo "Board: rp2040:rp2040:rpipico"
echo ""

BODY=$(curl -sS --compressed -w "\n%{http_code}" -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg s "$SKETCH" '{sketch:$s,board:"rp2040:rp2040:rpipico",libraries:[]}')")

CODE=$(echo "$BODY" | tail -n1)
JSON=$(echo "$BODY" | sed '$d')

echo "$JSON" | jq '.' 2>/dev/null || echo "$JSON"
echo "HTTP $CODE"
echo ""

if echo "$JSON" | jq -e '.success == true and .outputFormat == "uf2"' &>/dev/null; then
  echo "OK: UF2 firmware returned (base64 length $(echo "$JSON" | jq -r '.uf2 | length'))"
  exit 0
fi

if echo "$JSON" | jq -e '.success == false' &>/dev/null; then
  echo "Compile failed. If rawOutput mentions platform not found / 3rd party URL:"
  echo "  - Server must use ARDUINO_DOCKER_IMAGE built from docker/arduino-compile/Dockerfile (includes rp2040), or"
  echo "  - Host arduino-cli must have Earle Philhower index + arduino-cli core install rp2040:rp2040"
  exit 1
fi

exit 1
