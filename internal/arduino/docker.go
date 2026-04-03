package arduino

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// dockerBundledLibs: keys normalized with strings.ToLower (and common aliases).
// Must match BundledDockerLibraryNames in libcatalog.go and docker/arduino-compile/Dockerfile + Wire/SPI/EEPROM from cores (avr, rp2040, esp32, …).
var dockerBundledLibs = map[string]struct{}{
	// AVR core (no separate lib install)
	"servo": {}, "wire": {}, "spi": {}, "liquidcrystal": {}, "eeprom": {},
	// Dockerfile: arduino-cli lib install …
	"stepper":           {},
	"adafruit neopixel": {}, "adafruit_neopixel": {}, "neopixel": {},
	"dht sensor library": {}, "dht_sensor_library": {}, "dht": {},
	"ethernet": {}, "sd": {},
	"pubsubclient": {}, "arduinojson": {},
	"mfrc522": {}, "rtclib": {}, "onewire": {}, "dallastemperature": {},
	"accelstepper": {}, "fastled": {}, "irremote": {},
	"bounce2":              {},
	"adafruit gfx library": {}, "adafruit_gfx_library": {}, "adafruit gfx": {},
	"adafruit ssd1306": {}, "adafruit_ssd1306": {}, "ssd1306": {},
	"u8g2":                    {},
	"adafruit unified sensor": {}, "adafruit_unified_sensor": {},
	"adafruit busio": {}, "adafruit_busio": {},
}

// dockerExtraInstallable: optional on-demand installs (not in image). Keys → exact Library Manager names.
var dockerExtraInstallable = map[string]string{}

func validateLibrariesForDocker(libs []string) error {
	for _, lib := range libs {
		lib = strings.TrimSpace(lib)
		key := strings.ToLower(lib)
		if _, ok := dockerBundledLibs[key]; ok {
			continue
		}
		if _, ok := dockerExtraInstallable[key]; ok {
			continue
		}
		if _, ok := dockerExtraInstallable[strings.ReplaceAll(key, " ", "_")]; ok {
			continue
		}
		return fmt.Errorf("library %q is not available in container mode (unknown or not in allowlist; see dockerBundledLibs in internal/arduino/docker.go)", lib)
	}
	return nil
}

// dockerExtraInstallCanonical returns the registry name for an allowlisted extra library.
func dockerExtraInstallCanonical(lib string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(lib))
	if _, ok := dockerBundledLibs[key]; ok {
		return "", false
	}
	if c, ok := dockerExtraInstallable[key]; ok {
		return c, true
	}
	if c, ok := dockerExtraInstallable[strings.ReplaceAll(key, " ", "_")]; ok {
		return c, true
	}
	return "", false
}

func validateContainerRuntime(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	p, err := exec.LookPath(cfg.DockerBinary)
	if err != nil {
		return fmt.Errorf("container runtime not found in PATH (install Docker/Podman or set ARDUINO_DOCKER_BINARY): %w", err)
	}
	base := filepath.Base(p)
	switch {
	case strings.EqualFold(base, "docker"), strings.EqualFold(base, "docker.exe"),
		strings.EqualFold(base, "podman"), strings.EqualFold(base, "podman.exe"):
		return nil
	default:
		return fmt.Errorf("ARDUINO_DOCKER_BINARY must resolve to docker or podman, got %q", base)
	}
}

// runContainerLibInstall runs arduino-cli lib install into sketch/libraries (Arduino convention).
// Uses default container networking so the registry is reachable (one shot per library).
func runContainerLibInstall(ctx context.Context, cfg *Config, workDir, libraryCanonical string) error {
	hostWork, err := filepath.Abs(workDir)
	if err != nil {
		return err
	}
	libDir := filepath.Join(hostWork, "sketch", "libraries")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		return err
	}
	rt, err := exec.LookPath(cfg.DockerBinary)
	if err != nil {
		return err
	}
	args := []string{
		"run", "--rm",
		"-v", hostWork + ":/work",
		"-w", "/work",
		cfg.DockerImage,
		"arduino-cli", "lib", "install", libraryCanonical,
		"--install-dir", "/work/sketch/libraries",
		"--no-color",
	}
	cmd := exec.CommandContext(ctx, rt, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("%s\n%w", strings.TrimSpace(buf.String()), err)
	}
	return nil
}

// runContainerCompile runs arduino-cli compile with no network; sketch may include sketch/libraries from install step.
func runContainerCompile(ctx context.Context, cfg *Config, workDir, board string) (string, error) {
	hostWork, err := filepath.Abs(workDir)
	if err != nil {
		return "", err
	}
	rt, err := exec.LookPath(cfg.DockerBinary)
	if err != nil {
		return "", err
	}
	compileBoard := board
	esp32Mode := isESP32Board(board)
	if esp32Mode && !strings.Contains(board, "FlashMode=") {
		compileBoard = board + ":FlashMode=dio"
	}
	args := []string{
		"run", "--rm",
		"--network", "none",
		"-v", hostWork + ":/work",
		"-w", "/work",
		cfg.DockerImage,
		"arduino-cli", "compile",
		"-b", compileBoard,
		"--output-dir", "/work/build",
		"--warnings", "all",
		"--verbose",
	}
	if esp32Mode && qemuBridgeBuildFlag != "" {
		args = append(args, "--build-property", qemuBridgeBuildFlag)
	}
	args = append(args, "/work/sketch")
	cmd := exec.CommandContext(ctx, rt, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	runErr := cmd.Run()
	return buf.String(), runErr
}
