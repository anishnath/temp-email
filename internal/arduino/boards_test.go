package arduino

import (
	"testing"
)

func TestPublicBoardFQBNList_DefaultIncludesESP32(t *testing.T) {
	t.Setenv("ARDUINO_SUPPORTED_BOARD_FQBNS", "")
	found := false
	for _, b := range PublicBoardFQBNList() {
		if b == "esp32:esp32:esp32c3" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("default list should include esp32:esp32:esp32c3")
	}
}

func TestPublicBoardFQBNList_EnvOverride(t *testing.T) {
	t.Setenv("ARDUINO_SUPPORTED_BOARD_FQBNS", " a:b:c , d:e:f ")
	list := PublicBoardFQBNList()
	if len(list) != 2 || list[0] != "a:b:c" || list[1] != "d:e:f" {
		t.Fatalf("got %#v", list)
	}
}

func TestEnforceBoardAllowlist(t *testing.T) {
	t.Run("defaultOff", func(t *testing.T) {
		t.Setenv("ARDUINO_ENFORCE_BOARD_ALLOWLIST", "")
		if EnforceBoardAllowlist() {
			t.Fatal("default should be false")
		}
	})
	t.Run("on", func(t *testing.T) {
		t.Setenv("ARDUINO_ENFORCE_BOARD_ALLOWLIST", "true")
		if !EnforceBoardAllowlist() {
			t.Fatal("true should enable")
		}
	})
}
