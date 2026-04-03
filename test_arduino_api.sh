#!/bin/bash

# Test script for POST /api/arduino-compile
# Requires: server on localhost:8080; Docker image with arduino:avr + rp2040:rp2040 + esp32:esp32 (see docker/arduino-compile/Dockerfile) when using ARDUINO_DOCKER_IMAGE
# Usage: ./test_arduino_api.sh [base_url]
# curl --compressed: asks for gzip and decompresses for you.
# Manual unzip (raw gzip body, you gunzip): omit --compressed; pipe body to gunzip -c, e.g.:
#   curl -sS -H "Accept-Encoding: gzip" -H "Content-Type: application/json" \
#     -d '{"sketch":"...","board":"arduino:avr:uno"}' "$BASE_URL/api/arduino-compile" | gunzip -c | jq .
# Unit tests: go test ./internal/arduino/...

BASE_URL="${1:-http://localhost:8080}"

echo "Testing Arduino compile API"
echo "==========================="
echo "Base URL: $BASE_URL"
echo ""

show() {
  echo "$1" | jq '.' 2>/dev/null || echo "$1"
}

# 1. Validation: empty sketch -> 400
echo "1. Validation (empty sketch, expect 400):"
V1=$(curl -s --compressed -w "\n%{http_code}" -X POST "$BASE_URL/api/arduino-compile" \
  -H "Content-Type: application/json" \
  -d '{"sketch":"","board":"arduino:avr:uno"}')
CODE=$(echo "$V1" | tail -n1)
BODY=$(echo "$V1" | sed '$d')
show "$BODY"
echo "   HTTP $CODE"
echo ""

# 2. Validation: missing board -> 400
echo "2. Validation (missing board, expect 400):"
V2=$(curl -s --compressed -w "\n%{http_code}" -X POST "$BASE_URL/api/arduino-compile" \
  -H "Content-Type: application/json" \
  -d '{"sketch":"void setup(){} void loop(){}"}')
CODE=$(echo "$V2" | tail -n1)
BODY=$(echo "$V2" | sed '$d')
show "$BODY"
echo "   HTTP $CODE"
echo ""

# 3. Compile: minimal blink (success if arduino-cli + core installed)
echo "3. Compile blink sketch (200 + success, or 503 if arduino-cli missing):"
SKETCH='void setup() { pinMode(13, OUTPUT); }
void loop() { digitalWrite(13, HIGH); delay(1000); digitalWrite(13, LOW); delay(1000); }'
RESP=$(curl -s --compressed -w "\n%{http_code}" -X POST "$BASE_URL/api/arduino-compile" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg s "$SKETCH" '{sketch:$s,board:"arduino:avr:uno",libraries:[]}')")
CODE=$(echo "$RESP" | tail -n1)
BODY=$(echo "$RESP" | sed '$d')
show "$BODY"
echo "   HTTP $CODE"
if echo "$BODY" | jq -e '.success == true' &>/dev/null; then
  OF=$(echo "$BODY" | jq -r '.outputFormat // empty')
  if [[ "$OF" == "uf2" ]]; then
    echo "   -> Compile OK (outputFormat=uf2, uf2 base64 length: $(echo "$BODY" | jq -r '.uf2 | length'))"
  else
    echo "   -> Compile OK (outputFormat=${OF:-hex}, hex length: $(echo "$BODY" | jq -r '.hex | length'))"
  fi
elif echo "$BODY" | jq -e '.success == false' &>/dev/null 2>&1; then
  if [[ "$CODE" == "503" ]]; then
    echo "   -> arduino-cli not available (install CLI + arduino-cli core install arduino:avr)"
  else
    echo "   -> Compile reported failure (check core/libraries)"
  fi
fi
echo ""

# 4. RP2040 / Raspberry Pi Pico (Earle Philhower core — must be in compile image or host arduino-cli)
echo "4. Compile Pico blink (board rp2040:rp2040:rpipico, expect UF2 + success if rp2040 core installed):"
PICO_SKETCH='void setup() {
  pinMode(25, OUTPUT);
}
void loop() {
  digitalWrite(25, HIGH);
  delay(500);
  digitalWrite(25, LOW);
  delay(500);
}'
PICO=$(curl -s --compressed -w "\n%{http_code}" -X POST "$BASE_URL/api/arduino-compile" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg s "$PICO_SKETCH" '{sketch:$s,board:"rp2040:rp2040:rpipico",libraries:[]}')")
CODE=$(echo "$PICO" | tail -n1)
BODY=$(echo "$PICO" | sed '$d')
show "$BODY"
echo "   HTTP $CODE"
if echo "$BODY" | jq -e '.success == true' &>/dev/null; then
  OF=$(echo "$BODY" | jq -r '.outputFormat // empty')
  if [[ "$OF" == "uf2" ]]; then
    echo "   -> Pico OK (outputFormat=uf2, uf2 base64 length: $(echo "$BODY" | jq -r '.uf2 | length'))"
  else
    echo "   -> Unexpected outputFormat for Pico (want uf2): $OF"
  fi
elif echo "$BODY" | jq -e '.success == false' &>/dev/null 2>&1; then
  if [[ "$CODE" == "503" ]]; then
    echo "   -> Service unavailable (arduino-cli / Docker / Podman)"
  elif echo "$BODY" | grep -qi 'rp2040:rp2040.*not found'; then
    echo "   -> rp2040 core missing: rebuild docker/arduino-compile image or install rp2040 on host (see arduino.md)"
  else
    echo "   -> Compile failed (see rawOutput)"
  fi
fi
echo ""

# 5. ESP32 (Espressif core — must be in compile image; success → outputFormat "bin")
echo "5. Compile ESP32 blink (board esp32:esp32:esp32, expect bin + success if esp32 core installed):"
ESP32_SKETCH='void setup() {
  pinMode(2, OUTPUT);
}
void loop() {
  digitalWrite(2, HIGH);
  delay(500);
  digitalWrite(2, LOW);
  delay(500);
}'
ESP32=$(curl -s --compressed -w "\n%{http_code}" -X POST "$BASE_URL/api/arduino-compile" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg s "$ESP32_SKETCH" '{sketch:$s,board:"esp32:esp32:esp32",libraries:[]}')")
CODE=$(echo "$ESP32" | tail -n1)
BODY=$(echo "$ESP32" | sed '$d')
show "$BODY"
echo "   HTTP $CODE"
if echo "$BODY" | jq -e '.success == true' &>/dev/null; then
  OF=$(echo "$BODY" | jq -r '.outputFormat // empty')
  if [[ "$OF" == "bin" ]]; then
    echo "   -> ESP32 OK (outputFormat=bin, bin base64 length: $(echo "$BODY" | jq -r '.bin | length'))"
  else
    echo "   -> Unexpected outputFormat for ESP32 (want bin): $OF"
  fi
elif echo "$BODY" | jq -e '.success == false' &>/dev/null 2>&1; then
  if [[ "$CODE" == "503" ]]; then
    echo "   -> Service unavailable (arduino-cli / Docker / Podman)"
  elif echo "$BODY" | grep -qi 'esp32:esp32.*not found'; then
    echo "   -> esp32 core missing: rebuild docker/arduino-compile image or install esp32 on host (see arduino.md)"
  else
    echo "   -> Compile failed (see rawOutput)"
  fi
fi
echo ""

# 6. Compile error: typo in API name
echo "6. Compile error (typo digitalWrit, expect success:false, errors array):"
BAD=$(curl -s --compressed -X POST "$BASE_URL/api/arduino-compile" \
  -H "Content-Type: application/json" \
  -d '{"sketch":"void setup() { pinMode(13, OUTPUT); }\nvoid loop() { digitalWrit(13, HIGH); }","board":"arduino:avr:uno","libraries":[]}')
show "$BAD"
if echo "$BAD" | jq -e '.success == false and .error == "compile"' &>/dev/null; then
  echo "   -> Got compile failure response"
fi
echo ""

# 7. Multi-file (optional): sketch.ino + config.h
echo "7. Multi-file sketch (expect 200, success if runtime OK):"
MULTI=$(curl -s --compressed -w "\n%{http_code}" -X POST "$BASE_URL/api/arduino-compile" \
  -H "Content-Type: application/json" \
  -d "$(jq -n \
    --arg s 'void setup() { pinMode(LED_BUILTIN, OUTPUT); }
void loop() { digitalWrite(LED_BUILTIN, HIGH); delay(500); digitalWrite(LED_BUILTIN, LOW); delay(500); }' \
    --arg h '#define LED_BUILTIN 13' \
    '{sketch:$s,board:"arduino:avr:uno",libraries:[],files:[{name:"config.h",content:$h}]}')")
CODE=$(echo "$MULTI" | tail -n1)
BODY=$(echo "$MULTI" | sed '$d')
show "$BODY"
echo "   HTTP $CODE"
echo ""

# 8. Library API: overview (no network) + optional search (needs registry)
echo "8. GET /api/arduino-libraries (expect 200 + bundledDockerLibraries):"
LIBO=$(curl -sS --compressed -w "\n%{http_code}" "$BASE_URL/api/arduino-libraries")
CODE=$(echo "$LIBO" | tail -n1)
BODY=$(echo "$LIBO" | sed '$d')
show "$BODY" | head -c 800
echo ""
echo "   HTTP $CODE"
echo ""

echo "9. GET /api/arduino-libraries/search?q=neo (200 if arduino-cli + network OK):"
LIBS=$(curl -sS --compressed -w "\n%{http_code}" "$BASE_URL/api/arduino-libraries/search?q=neo")
CODE=$(echo "$LIBS" | tail -n1)
BODY=$(echo "$LIBS" | sed '$d')
show "$BODY" | head -c 600
echo ""
echo "   HTTP $CODE"
echo ""

echo "Done. Pico-only: ./test_arduino_pico_api.sh $BASE_URL | ESP32-only: ./test_arduino_esp32_api.sh $BASE_URL"
echo "Unit tests: go test ./internal/arduino/... -count=1"
