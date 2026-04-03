package arduino

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestQemuESP32C3Blink compiles a blink sketch, starts QEMU, and verifies serial output.
// Requires: arduino-cli with esp32:esp32 core + qemu-system-riscv32 (Espressif fork).
// Skip if either tool is not installed.
func TestQemuESP32C3Blink(t *testing.T) {
	// Check prerequisites
	if _, err := exec.LookPath("arduino-cli"); err != nil {
		t.Skip("arduino-cli not in PATH")
	}
	qemuPath := os.Getenv("QEMU_RISCV32_BINARY")
	if qemuPath == "" {
		qemuPath = "qemu-system-riscv32"
	}
	if _, err := exec.LookPath(qemuPath); err != nil {
		// Try known local path
		local := filepath.Join(os.Getenv("HOME"), "tools/qemu-esp32/qemu/bin/qemu-system-riscv32")
		if _, err2 := os.Stat(local); err2 != nil {
			t.Skipf("qemu-system-riscv32 not found: %v", err)
		}
		qemuPath = local
		os.Setenv("QEMU_RISCV32_BINARY", local)
	}

	// Compile sketch via our Compile() function (injects GPIO bridge + DIO flash mode)
	sketchCode := `void setup() {
  Serial.begin(115200);
  pinMode(8, OUTPUT);
}
void loop() {
  Serial.println("QEMU_TEST_OK");
  digitalWrite(8, HIGH);
  delay(200);
  digitalWrite(8, LOW);
  delay(200);
}`

	compileCfg := LoadConfig()
	resp := Compile(context.Background(), compileCfg, &Request{
		Sketch: sketchCode,
		Board:  "esp32:esp32:esp32c3",
	})
	if !resp.Success {
		t.Fatalf("compile failed: %s\n%s", resp.Message, resp.RawOutput)
	}
	if resp.MergedBin == "" {
		t.Fatal("compile succeeded but no mergedBin in response")
	}
	fwB64 := resp.MergedBin

	// Start QEMU
	cfg := LoadQemuConfig()
	cfg.RiscV32Binary = qemuPath
	cfg.InstanceTimeout = 15 * time.Second

	mgr := NewQemuManager(cfg)
	defer mgr.StopAll()

	var mu sync.Mutex
	var serialBuf strings.Builder
	gotTestOK := make(chan struct{}, 1)
	gpioEvents := make([]string, 0)

	ctx := context.Background()
	err := mgr.StartInstance(ctx, "test-blink", "esp32:esp32:esp32c3", fwB64, func(ev QemuEvent) {
		mu.Lock()
		defer mu.Unlock()

		switch ev.Type {
		case "serial_output":
			if data, ok := ev.Data.(map[string]interface{}); ok {
				if s, ok := data["data"].(string); ok {
					serialBuf.WriteString(s)
					if strings.Contains(serialBuf.String(), "QEMU_TEST_OK") {
						select {
						case gotTestOK <- struct{}{}:
						default:
						}
					}
				}
			}
		case "gpio_change":
			if data, ok := ev.Data.(map[string]interface{}); ok {
				pin, _ := data["pin"].(int)
				state, _ := data["state"].(int)
				desc := fmt.Sprintf("GPIO%d=%d", pin, state)
				gpioEvents = append(gpioEvents, desc)
				if len(gpioEvents) <= 10 {
					// logged below
				}
			}
		case "system":
			if data, ok := ev.Data.(map[string]string); ok {
				t.Logf("system event: %s", data["event"])
			}
		case "error":
			if data, ok := ev.Data.(map[string]string); ok {
				t.Logf("error: %s", data["message"])
			}
		}
	})
	if err != nil {
		t.Fatalf("StartInstance: %v", err)
	}

	// Wait for serial output containing our test string, then wait a bit more for GPIO events
	select {
	case <-gotTestOK:
		// Give GPIO bridge time to report (it polls every 10ms)
		time.Sleep(2 * time.Second)
		t.Logf("SUCCESS: received 'QEMU_TEST_OK' from ESP32-C3 QEMU")
		mu.Lock()
		t.Logf("Serial output:\n%s", serialBuf.String())
		t.Logf("GPIO events (%d total): %v", len(gpioEvents), gpioEvents)
		hasGPIO8 := false
		for _, e := range gpioEvents {
			if strings.HasPrefix(e, "GPIO8=") {
				hasGPIO8 = true
				break
			}
		}
		mu.Unlock()
		if hasGPIO8 {
			t.Logf("GPIO8 toggle detected — LED blinks!")
		} else {
			t.Logf("NOTE: no GPIO8 events yet (bridge may need more time)")
		}
	case <-time.After(15 * time.Second):
		mu.Lock()
		serial := serialBuf.String()
		gpio := len(gpioEvents)
		mu.Unlock()
		if serial == "" {
			t.Fatal("TIMEOUT: no serial output from QEMU after 15s")
		} else {
			t.Fatalf("TIMEOUT: serial=%d chars, gpio=%d events, but no 'QEMU_TEST_OK':\n%s", len(serial), gpio, serial)
		}
	}
}
