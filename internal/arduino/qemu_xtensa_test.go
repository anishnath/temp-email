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

// TestQemuESP32XtensaBlink compiles a blink sketch for ESP32 (Xtensa),
// starts QEMU, and verifies serial output.
func TestQemuESP32XtensaBlink(t *testing.T) {
	if _, err := exec.LookPath("arduino-cli"); err != nil {
		t.Skip("arduino-cli not in PATH")
	}
	qemuPath := os.Getenv("QEMU_XTENSA_BINARY")
	if qemuPath == "" {
		qemuPath = "qemu-system-xtensa"
	}
	if _, err := exec.LookPath(qemuPath); err != nil {
		local := filepath.Join(os.Getenv("HOME"), "tools/qemu-esp32/qemu/bin/qemu-system-xtensa")
		if _, err2 := os.Stat(local); err2 != nil {
			t.Skipf("qemu-system-xtensa not found: %v", err)
		}
		qemuPath = local
		os.Setenv("QEMU_XTENSA_BINARY", local)
	}

	sketchCode := `void setup() {
  Serial.begin(115200);
  pinMode(2, OUTPUT);
}
void loop() {
  Serial.println("XTENSA_TEST_OK");
  digitalWrite(2, HIGH);
  delay(200);
  digitalWrite(2, LOW);
  delay(200);
}`

	compileCfg := LoadConfig()
	resp := Compile(context.Background(), compileCfg, &Request{
		Sketch: sketchCode,
		Board:  "esp32:esp32:esp32",
	})
	if !resp.Success {
		t.Fatalf("compile failed: %s\n%s", resp.Message, resp.RawOutput)
	}
	if resp.MergedBin == "" && resp.JobID == "" {
		t.Fatal("compile succeeded but no mergedBin or jobId")
	}

	cfg := LoadQemuConfig()
	cfg.XtensaBinary = qemuPath
	cfg.InstanceTimeout = 15 * time.Second

	mgr := NewQemuManager(cfg)
	defer mgr.StopAll()

	var mu sync.Mutex
	var serialBuf strings.Builder
	gpioEvents := make([]string, 0)
	gotTestOK := make(chan struct{}, 1)

	err := mgr.StartInstance(context.Background(), "test-xtensa", "esp32:esp32:esp32",
		resp.MergedBin, func(ev QemuEvent) {
			mu.Lock()
			defer mu.Unlock()

			switch ev.Type {
			case "serial_output":
				if data, ok := ev.Data.(map[string]interface{}); ok {
					if s, ok := data["data"].(string); ok {
						serialBuf.WriteString(s)
						if strings.Contains(serialBuf.String(), "XTENSA_TEST_OK") {
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
					gpioEvents = append(gpioEvents, fmt.Sprintf("GPIO%d=%d", pin, state))
				}
			case "system":
				if data, ok := ev.Data.(map[string]string); ok {
					t.Logf("system: %s", data["event"])
				}
			}
		})
	if err != nil {
		t.Fatalf("StartInstance: %v", err)
	}

	select {
	case <-gotTestOK:
		time.Sleep(2 * time.Second)
		mu.Lock()
		t.Logf("SUCCESS: received 'XTENSA_TEST_OK'")
		t.Logf("Serial: %s", serialBuf.String())
		t.Logf("GPIO events (%d): %v", len(gpioEvents), gpioEvents)
		mu.Unlock()
	case <-time.After(15 * time.Second):
		mu.Lock()
		serial := serialBuf.String()
		mu.Unlock()
		if serial == "" {
			t.Fatal("TIMEOUT: no serial output from QEMU Xtensa after 15s")
		} else {
			t.Fatalf("TIMEOUT: got serial but no 'XTENSA_TEST_OK':\n%s", serial)
		}
	}
}
