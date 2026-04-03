package arduino

import (
	"fmt"
	"path/filepath"
	"strings"
)

// validateSketchSource rejects bytes that are unsafe or invalid in source text.
// Shell injection is not applicable (we use exec.Command argv, not sh -c), but NUL
// and most ASCII control characters break or confuse toolchains.
func validateSketchSource(s string) error {
	if strings.IndexByte(s, 0) >= 0 {
		return fmt.Errorf("sketch must not contain null bytes")
	}
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return fmt.Errorf("sketch contains disallowed control characters")
		}
	}
	return nil
}

// validateResolvedArduinoCLI ensures the resolved binary is actually arduino-cli,
// not a shell or other executable (defense when ARDUINO_CLI is misconfigured).
func validateResolvedArduinoCLI(resolvedPath string) error {
	base := filepath.Base(resolvedPath)
	switch {
	case strings.EqualFold(base, "arduino-cli"):
		return nil
	case strings.EqualFold(base, "arduino-cli.exe"):
		return nil
	default:
		return fmt.Errorf("ARDUINO_CLI must resolve to arduino-cli executable, got %q", base)
	}
}

// validateDataDir rejects shell metacharacters and newlines in ARDUINO_COMPILE_DATA_DIR.
func validateDataDir(dir string) error {
	if dir == "" {
		return nil
	}
	if strings.IndexByte(dir, 0) >= 0 {
		return fmt.Errorf("invalid ARDUINO_COMPILE_DATA_DIR")
	}
	if strings.ContainsAny(dir, "\n\r;|&`") {
		return fmt.Errorf("invalid ARDUINO_COMPILE_DATA_DIR")
	}
	// Command substitution in shells
	if strings.Contains(dir, "$(") || strings.Contains(dir, "${") {
		return fmt.Errorf("invalid ARDUINO_COMPILE_DATA_DIR")
	}
	return nil
}

// validateDockerImageRef rejects characters that could break argv when passed to docker run.
func validateDockerImageRef(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("Docker image name is empty")
	}
	if strings.ContainsAny(name, "\n\r;|&`") {
		return fmt.Errorf("invalid Docker image reference")
	}
	if strings.Contains(name, "$(") || strings.Contains(name, "${") {
		return fmt.Errorf("invalid Docker image reference")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid Docker image reference")
		}
	}
	return nil
}
