package arduino

import (
	"strings"
	"testing"
)

func TestValidateSketchSource(t *testing.T) {
	if err := validateSketchSource("void setup() {}"); err != nil {
		t.Fatal(err)
	}
	if err := validateSketchSource("a\nb\tc\r\nd"); err != nil {
		t.Fatal(err)
	}
	if err := validateSketchSource("bad\x00null"); err == nil {
		t.Fatal("want error for NUL")
	}
	if err := validateSketchSource("bad\x01"); err == nil {
		t.Fatal("want error for control char")
	}
}

func TestValidateResolvedArduinoCLI(t *testing.T) {
	if err := validateResolvedArduinoCLI("/usr/local/bin/arduino-cli"); err != nil {
		t.Fatal(err)
	}
	if err := validateResolvedArduinoCLI("/opt/Arduino/arduino-cli.exe"); err != nil {
		t.Fatal(err)
	}
	if err := validateResolvedArduinoCLI("/bin/bash"); err == nil {
		t.Fatal("want error for non-arduino-cli")
	}
}

func TestValidateDataDir(t *testing.T) {
	if err := validateDataDir(""); err != nil {
		t.Fatal(err)
	}
	if err := validateDataDir("/var/lib/arduino-cli-data"); err != nil {
		t.Fatal(err)
	}
	// Windows-style path with parentheses
	if err := validateDataDir(`C:\Program Files (x86)\Arduino15`); err != nil {
		t.Fatal(err)
	}
	if err := validateDataDir("/tmp/foo;rm -rf"); err == nil {
		t.Fatal("want error")
	}
	if err := validateDataDir("/tmp/foo$(id)"); err == nil {
		t.Fatal("want error")
	}
}

func TestValidateSketchSource_UTF8(t *testing.T) {
	// Comment in non-ASCII should be allowed
	s := "// 日本語\nvoid setup() {}"
	if err := validateSketchSource(s); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSketchSource_Long(t *testing.T) {
	s := strings.Repeat("a", 10000) + "\n"
	if err := validateSketchSource(s); err != nil {
		t.Fatal(err)
	}
}
