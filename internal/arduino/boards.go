package arduino

import (
	"os"
	"strings"
)

// DefaultPublicBoardFQBNs is the suggested board list for UIs (GET /api/arduino-libraries → supportedBoardFQBNs).
// The compile API does not enforce this unless ARDUINO_ENFORCE_BOARD_ALLOWLIST=true.
var DefaultPublicBoardFQBNs = []string{
	"arduino:avr:uno",
	"arduino:avr:nano",
	"arduino:avr:mega",
	"rp2040:rp2040:rpipico",
	"rp2040:rp2040:rpipicow",
	"esp32:esp32:esp32",
	"esp32:esp32:esp32c3",
	"esp32:esp32:esp32s3",
}

// PublicBoardFQBNList returns FQBNs advertised to clients for dropdowns / validation.
// If ARDUINO_SUPPORTED_BOARD_FQBNS is set (comma-separated), returns that list only; otherwise DefaultPublicBoardFQBNs.
func PublicBoardFQBNList() []string {
	raw := strings.TrimSpace(os.Getenv("ARDUINO_SUPPORTED_BOARD_FQBNS"))
	if raw == "" {
		return append([]string(nil), DefaultPublicBoardFQBNs...)
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), DefaultPublicBoardFQBNs...)
	}
	return out
}

// EnforceBoardAllowlist reports whether compile requests must use only PublicBoardFQBNList() entries.
func EnforceBoardAllowlist() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("ARDUINO_ENFORCE_BOARD_ALLOWLIST")), "true")
}

func boardAllowedByPolicy(board string) bool {
	board = strings.TrimSpace(board)
	for _, b := range PublicBoardFQBNList() {
		if b == board {
			return true
		}
	}
	return false
}
