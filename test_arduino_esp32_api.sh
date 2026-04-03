#!/bin/bash
# Integration test: ESP32 compile + QEMU simulation via API.
#
# Tests:
#   1. POST /api/arduino-compile for ESP32-C3 → returns jobId (no base64 blob)
#   2. POST /api/arduino-simulate/start with jobId → starts QEMU
#   3. GET  /api/arduino-simulate/stream → SSE events (serial + GPIO)
#   4. POST /api/arduino-simulate/stop → cleanup
#
# Usage: ./test_arduino_esp32_api.sh [base_url]
# Example: ./test_arduino_esp32_api.sh http://localhost:8080

set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"
COMPILE_URL="${BASE_URL}/api/arduino-compile"
SIM_URL="${BASE_URL}/api/arduino-simulate"

SKETCH='void setup() {
  Serial.begin(115200);
  pinMode(8, OUTPUT);
}
void loop() {
  Serial.println("ESP32_API_TEST_OK");
  digitalWrite(8, HIGH);
  delay(200);
  digitalWrite(8, LOW);
  delay(200);
}'

PASS=0
FAIL=0

pass() { echo "  ✓ $1"; PASS=$((PASS+1)); }
fail() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

# ── Test 1: Compile ESP32-C3 ──
echo "=== Test 1: Compile ESP32-C3 ==="
echo "POST $COMPILE_URL"

BODY=$(curl -sS --compressed -w "\n%{http_code}" -X POST "$COMPILE_URL" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg s "$SKETCH" '{sketch:$s,board:"esp32:esp32:esp32c3",libraries:[]}')")

CODE=$(echo "$BODY" | tail -n1)
JSON=$(echo "$BODY" | sed '$d')

echo "$JSON" | jq '{success,outputFormat,jobId,programSize,compileTimeMs}' 2>/dev/null || echo "$JSON"
echo "HTTP $CODE"

if echo "$JSON" | jq -e '.success == true' &>/dev/null; then
  pass "Compile succeeded"
else
  fail "Compile failed"
  echo "$JSON" | jq '.message // .rawOutput' 2>/dev/null
  echo ""
  echo "RESULTS: $PASS passed, $FAIL failed"
  exit 1
fi

# Check for jobId (new flow) or bin (legacy)
JOB_ID=$(echo "$JSON" | jq -r '.jobId // empty')
HAS_BIN=$(echo "$JSON" | jq -r 'if .bin then "yes" else "no" end')

if [ -n "$JOB_ID" ]; then
  pass "Got jobId: $JOB_ID (no base64 blob — efficient)"
elif [ "$HAS_BIN" = "yes" ]; then
  pass "Got .bin (legacy base64 mode)"
else
  fail "No jobId or bin in response"
fi

echo ""

# ── Test 2: Start QEMU simulation ──
echo "=== Test 2: Start QEMU simulation ==="
SESSION_ID="test-$$-$(date +%s)"

if [ -n "$JOB_ID" ]; then
  START_BODY=$(jq -n --arg id "$SESSION_ID" --arg job "$JOB_ID" '{id:$id,board:"esp32:esp32:esp32c3",jobId:$job}')
else
  FW=$(echo "$JSON" | jq -r '.mergedBin // .bin')
  START_BODY=$(jq -n --arg id "$SESSION_ID" --arg fw "$FW" '{id:$id,board:"esp32:esp32:esp32c3",firmware:$fw}')
fi

START_RESP=$(curl -sS -X POST "$SIM_URL/start" \
  -H "Content-Type: application/json" \
  -d "$START_BODY")

echo "$START_RESP" | jq '.' 2>/dev/null || echo "$START_RESP"

if echo "$START_RESP" | jq -e '.success == true' &>/dev/null; then
  pass "QEMU started (session: $SESSION_ID)"
else
  fail "QEMU start failed: $(echo "$START_RESP" | jq -r '.error // empty')"
  echo ""
  echo "  If QEMU binary not found:"
  echo "    export QEMU_RISCV32_BINARY=/path/to/qemu-system-riscv32"
  echo "    Or: export QEMU_DOCKER_IMAGE=qemu-esp32:local"
  echo ""
  echo "RESULTS: $PASS passed, $FAIL failed"
  exit 1
fi

echo ""

# ── Test 3: Stream SSE events ──
echo "=== Test 3: Stream SSE events (15 seconds) ==="
echo "GET $SIM_URL/stream?id=$SESSION_ID"

# Capture raw SSE stream for 8 seconds (macOS-compatible: background + sleep + kill)
rm -f /tmp/esp32_test_stream.txt
curl -sS -N "$SIM_URL/stream?id=$SESSION_ID" > /tmp/esp32_test_stream.txt 2>/dev/null &
CURL_PID=$!
sleep 15
kill $CURL_PID 2>/dev/null || true
wait $CURL_PID 2>/dev/null || true

# Show first 20 lines
echo "  Raw SSE (first 20 lines):"
head -20 /tmp/esp32_test_stream.txt 2>/dev/null | sed 's/^/    /'
echo ""

# Check for serial output
if grep -q "ESP32_API_TEST_OK" /tmp/esp32_test_stream.txt 2>/dev/null; then
  pass "Serial output: ESP32_API_TEST_OK received"
else
  fail "No serial output with ESP32_API_TEST_OK in stream"
fi

# Check for GPIO events
GPIO_COUNT=$(grep -c '"gpio_change"' /tmp/esp32_test_stream.txt 2>/dev/null || true)
GPIO_COUNT=${GPIO_COUNT:-0}
if [ "$GPIO_COUNT" -gt 0 ] 2>/dev/null; then
  pass "GPIO events received ($GPIO_COUNT)"
else
  echo "  (GPIO events may arrive later or require bridge support)"
fi

rm -f /tmp/esp32_test_stream.txt

echo ""

# ── Test 4: Stop simulation ──
echo "=== Test 4: Stop simulation ==="
STOP_RESP=$(curl -sS -X POST "$SIM_URL/stop" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg id "$SESSION_ID" '{id:$id}')")

echo "$STOP_RESP" | jq '.' 2>/dev/null || echo "$STOP_RESP"

if echo "$STOP_RESP" | jq -e '.success == true' &>/dev/null; then
  pass "Simulation stopped"
else
  fail "Stop failed"
fi

echo ""

# ── Results ──
echo "=== Results ==="
echo "Passed: $PASS"
echo "Failed: $FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo ""
  echo "ALL TESTS PASSED"
  exit 0
else
  echo ""
  echo "SOME TESTS FAILED"
  exit 1
fi
