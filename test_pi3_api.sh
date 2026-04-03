#!/bin/bash
# Integration test: Raspberry Pi 3 QEMU simulation via API.
#
# Tests:
#   1. POST /api/pi-simulate/start → boots Pi 3 in QEMU
#   2. GET  /api/pi-simulate/stream → SSE events (serial terminal output)
#   3. POST /api/pi-simulate/input → send command to terminal
#   4. POST /api/pi-simulate/stop → cleanup
#
# Requires: PI_QEMU_DOCKER_IMAGE=qemu-pi3:local or host QEMU + Pi OS files.
#
# Usage: ./test_pi3_api.sh [base_url]
# Example: ./test_pi3_api.sh http://localhost:8080

set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"
SIM_URL="${BASE_URL}/api/pi-simulate"
SESSION_ID="pi-test-$$-$(date +%s)"

PASS=0
FAIL=0

pass() { echo "  ✓ $1"; PASS=$((PASS+1)); }
fail() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

# ── Test 1: Start Pi 3 QEMU ──
echo "=== Test 1: Start Pi 3 QEMU ==="
echo "POST $SIM_URL/start"

START_RESP=$(curl -sS -X POST "$SIM_URL/start" \
  -H "Content-Type: application/json" \
  -d "$(printf '{"id":"%s"}' "$SESSION_ID")")

echo "$START_RESP" | jq '.' 2>/dev/null || echo "$START_RESP"

if echo "$START_RESP" | jq -e '.success == true' &>/dev/null; then
  pass "Pi 3 QEMU started (session: $SESSION_ID)"
else
  fail "Pi 3 QEMU start failed: $(echo "$START_RESP" | jq -r '.error // empty')"
  echo ""
  echo "  Ensure one of:"
  echo "    PI_QEMU_DOCKER_IMAGE=qemu-pi3:local  (docker build -t qemu-pi3:local -f docker/qemu-pi3/Dockerfile .)"
  echo "    Or host mode: QEMU_AARCH64_BINARY + PI_KERNEL_PATH + PI_DTB_PATH + PI_SD_IMAGE_PATH"
  echo ""
  echo "RESULTS: $PASS passed, $FAIL failed"
  exit 1
fi

echo ""

# ── Test 2: Stream SSE events (wait for boot) ──
echo "=== Test 2: Stream SSE events (60 seconds — Pi boots slowly) ==="
echo "GET $SIM_URL/stream?id=$SESSION_ID"

rm -f /tmp/pi3_test_stream.txt
curl -sS -N "$SIM_URL/stream?id=$SESSION_ID" >> /tmp/pi3_test_stream.txt 2>/dev/null &
CURL_PID=$!

# Keep stream alive the entire test — don't kill it until test 4
# Poll for serial output every 5 seconds for up to 60 seconds
echo "  Waiting for Pi to boot (checking every 5s)..."
BOOT_WAIT=0
while [ $BOOT_WAIT -lt 60 ]; do
  sleep 5
  BOOT_WAIT=$((BOOT_WAIT+5))
  LINES=$(wc -l < /tmp/pi3_test_stream.txt 2>/dev/null | tr -d ' ')
  HAS_SERIAL=$(grep -c '"serial_output"' /tmp/pi3_test_stream.txt 2>/dev/null || true)
  echo "  ... ${BOOT_WAIT}s: ${LINES} SSE lines, ${HAS_SERIAL} serial events"
  if [ "${HAS_SERIAL:-0}" -gt "5" ]; then
    echo "  Serial output detected — Pi is booting!"
    break
  fi
done

echo "  Raw SSE (first 30 lines):"
head -30 /tmp/pi3_test_stream.txt 2>/dev/null | sed 's/^/    /'
echo ""

# Check for boot events
if grep -q '"booting"' /tmp/pi3_test_stream.txt 2>/dev/null; then
  pass "Got 'booting' event"
else
  fail "No 'booting' event"
fi

if grep -q '"booted"' /tmp/pi3_test_stream.txt 2>/dev/null; then
  pass "Got 'booted' event (serial connected)"
else
  fail "No 'booted' event (QEMU may still be starting)"
fi

if grep -q '"serial_output"' /tmp/pi3_test_stream.txt 2>/dev/null; then
  pass "Got serial output from Pi"
else
  fail "No serial output (Pi may need more boot time)"
fi

# Check for Linux boot messages
if grep -q "login\|Linux\|kernel\|Raspberry\|raspberrypi\|Debian" /tmp/pi3_test_stream.txt 2>/dev/null; then
  pass "Linux boot messages detected"
else
  echo "  (No Linux boot messages yet — may need longer boot time)"
fi

echo ""

# ── Test 3: Send command to terminal (stream still alive) ──
echo "=== Test 3: Send command to terminal ==="
echo "POST $SIM_URL/input"

INPUT_RESP=$(curl -sS -X POST "$SIM_URL/input" \
  -H "Content-Type: application/json" \
  -d "$(printf '{"id":"%s","data":"echo PI3_TEST_OK\\n"}' "$SESSION_ID")")

echo "$INPUT_RESP" | jq '.' 2>/dev/null || echo "$INPUT_RESP"

if echo "$INPUT_RESP" | jq -e '.success == true' &>/dev/null; then
  pass "Serial input sent"
else
  fail "Serial input failed: $(echo "$INPUT_RESP" | jq -r '.error // empty')"
fi

# Wait a bit for response to appear in stream
sleep 3
if grep -q "PI3_TEST_OK" /tmp/pi3_test_stream.txt 2>/dev/null; then
  pass "Got PI3_TEST_OK echo back from Pi terminal"
else
  echo "  (echo response may not appear — Pi might not have a shell yet)"
fi

echo ""

# ── Test 4: Stop simulation (kill stream first) ──
echo "=== Test 4: Stop simulation ==="

# Kill the SSE stream curl BEFORE stopping — otherwise auto-stop races
kill $CURL_PID 2>/dev/null || true
wait $CURL_PID 2>/dev/null || true
sleep 1

STOP_RESP=$(curl -sS -X POST "$SIM_URL/stop" \
  -H "Content-Type: application/json" \
  -d "$(printf '{"id":"%s"}' "$SESSION_ID")")

echo "$STOP_RESP" | jq '.' 2>/dev/null || echo "$STOP_RESP"

if echo "$STOP_RESP" | jq -e '.success == true' &>/dev/null; then
  pass "Simulation stopped"
else
  fail "Stop failed"
fi

rm -f /tmp/pi3_test_stream.txt

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
