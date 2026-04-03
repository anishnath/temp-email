package arduino

import (
	"sort"
	"strings"
)

// BundledDockerLibraryNames are exact Library Manager names installed in docker/arduino-compile/Dockerfile
// (arduino-cli lib install …). Keep in sync with that file and dockerBundledLibs aliases.
var BundledDockerLibraryNames = []string{
	"Servo",
	"LiquidCrystal",
	"Stepper",
	"Adafruit NeoPixel",
	"DHT sensor library",
	"Ethernet",
	"SD",
	"PubSubClient",
	"ArduinoJson",
	"MFRC522",
	"RTClib",
	"OneWire",
	"DallasTemperature",
	"AccelStepper",
	"FastLED",
	"IRremote",
	"Bounce2",
	"Adafruit GFX Library",
	"Adafruit SSD1306",
	"U8g2",
}

// CoreBundledLibraryIDs are provided by board cores (arduino:avr, rp2040, etc.), not Library Manager.
var CoreBundledLibraryIDs = []string{
	"Wire", "SPI", "EEPROM",
}

// ExtraInstallableLibraryMap is optional on-demand installs for Docker compile (key → exact registry name).
// Populated from dockerExtraInstallable; empty means no extras beyond the image.
func ExtraInstallableLibraryMap() map[string]string {
	out := make(map[string]string, len(dockerExtraInstallable))
	for k, v := range dockerExtraInstallable {
		out[k] = v
	}
	return out
}

// LibraryAllowedForDockerCompile reports whether lib may appear in compile requests when using ARDUINO_DOCKER_IMAGE.
func LibraryAllowedForDockerCompile(lib string) bool {
	lib = strings.TrimSpace(lib)
	if lib == "" {
		return false
	}
	return validateLibrariesForDocker([]string{lib}) == nil
}

// SortedBundledDockerLibraryNames returns a copy of BundledDockerLibraryNames sorted alphabetically.
func SortedBundledDockerLibraryNames() []string {
	out := append([]string(nil), BundledDockerLibraryNames...)
	sort.Strings(out)
	return out
}
