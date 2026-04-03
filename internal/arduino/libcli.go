package arduino

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	libCLITimeout     = 90 * time.Second
	libSearchQueryMax = 128
	libInstallTimeout = 10 * time.Minute
)

// LibListJSON runs `arduino-cli lib list --format json` in Docker (if cfg.DockerImage) or on the host.
func LibListJSON(ctx context.Context, cfg *Config) ([]byte, error) {
	if cfg == nil {
		cfg = LoadConfig()
	}
	ctx, cancel := context.WithTimeout(ctx, libCLITimeout)
	defer cancel()
	if strings.TrimSpace(cfg.DockerImage) != "" {
		if err := validateDockerImageRef(cfg.DockerImage); err != nil {
			return nil, err
		}
		if err := validateContainerRuntime(cfg); err != nil {
			return nil, err
		}
		return dockerArduinoCLI(ctx, cfg, "lib", "list", "--format", "json")
	}
	cli, err := exec.LookPath(cfg.ArduinoCLIPath)
	if err != nil {
		return nil, fmt.Errorf("arduino-cli not in PATH: %w", err)
	}
	if err := validateResolvedArduinoCLI(cli); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, cli, "lib", "list", "--format", "json")
	cmd.Env = arduinoCLIEnv(cfg)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w", strings.TrimSpace(buf.String()), err)
	}
	return buf.Bytes(), nil
}

// LibSearchJSON runs `arduino-cli lib search <query> --format json` (requires network).
func LibSearchJSON(ctx context.Context, cfg *Config, query string) ([]byte, error) {
	if cfg == nil {
		cfg = LoadConfig()
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("search query is required")
	}
	if len(query) > libSearchQueryMax {
		return nil, fmt.Errorf("search query too long (max %d)", libSearchQueryMax)
	}
	ctx, cancel := context.WithTimeout(ctx, libCLITimeout)
	defer cancel()
	if strings.TrimSpace(cfg.DockerImage) != "" {
		if err := validateDockerImageRef(cfg.DockerImage); err != nil {
			return nil, err
		}
		if err := validateContainerRuntime(cfg); err != nil {
			return nil, err
		}
		// Default network (not --network none) so the registry is reachable.
		return dockerArduinoCLI(ctx, cfg, "lib", "search", query, "--format", "json")
	}
	cli, err := exec.LookPath(cfg.ArduinoCLIPath)
	if err != nil {
		return nil, fmt.Errorf("arduino-cli not in PATH: %w", err)
	}
	if err := validateResolvedArduinoCLI(cli); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, cli, "lib", "search", query, "--format", "json")
	cmd.Env = arduinoCLIEnv(cfg)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w", strings.TrimSpace(buf.String()), err)
	}
	return buf.Bytes(), nil
}

// LibInstall runs `arduino-cli lib install <name>` on the host only (mutates ARDUINO_DIRECTORIES_DATA).
// Not used when compiling via Docker image (use compile request libraries[] instead).
func LibInstall(ctx context.Context, cfg *Config, library string) ([]byte, error) {
	if cfg == nil {
		cfg = LoadConfig()
	}
	if strings.TrimSpace(cfg.DockerImage) != "" {
		return nil, fmt.Errorf("host lib install is disabled when ARDUINO_DOCKER_IMAGE is set; use POST /api/arduino-compile with libraries[]")
	}
	library = strings.TrimSpace(library)
	if library == "" {
		return nil, fmt.Errorf("library name is required")
	}
	if !libNamePattern.MatchString(library) {
		return nil, fmt.Errorf("invalid library name")
	}
	ctx, cancel := context.WithTimeout(ctx, libInstallTimeout)
	defer cancel()
	cli, err := exec.LookPath(cfg.ArduinoCLIPath)
	if err != nil {
		return nil, fmt.Errorf("arduino-cli not in PATH: %w", err)
	}
	if err := validateResolvedArduinoCLI(cli); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, cli, "lib", "install", library, "--no-color")
	cmd.Env = arduinoCLIEnv(cfg)
	if cfg.DataDir != "" {
		_ = os.MkdirAll(cfg.DataDir, 0o755)
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w", strings.TrimSpace(buf.String()), err)
	}
	return buf.Bytes(), nil
}

func dockerArduinoCLI(ctx context.Context, cfg *Config, args ...string) ([]byte, error) {
	rt, err := exec.LookPath(cfg.DockerBinary)
	if err != nil {
		return nil, err
	}
	full := append([]string{
		"run", "--rm",
		cfg.DockerImage,
		"arduino-cli",
	}, args...)
	cmd := exec.CommandContext(ctx, rt, full...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w", strings.TrimSpace(buf.String()), err)
	}
	return buf.Bytes(), nil
}

// SanitizeLibSearchQuery trims and validates query for logging / CLI.
func SanitizeLibSearchQuery(q string) (string, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return "", fmt.Errorf("query is required")
	}
	if len(q) > libSearchQueryMax {
		return "", fmt.Errorf("query too long")
	}
	return q, nil
}
