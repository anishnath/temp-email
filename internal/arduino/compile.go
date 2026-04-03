// Package arduino runs arduino-cli in an isolated temp sketch directory and cleans up afterward.
package arduino

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSketchMaxBytes = 50 * 1024
	defaultCompileTimeout = 10 * time.Minute
	defaultCleanupAfter   = 2 * time.Minute
	maxLibraries          = 32
	maxSketchFiles        = 64 // main sketch.ino + tabs + headers/sources
	mainSketchFile        = "sketch.ino"
)

// SketchFile is an extra sketch-folder file (same directory as sketch.ino).
type SketchFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// Config controls compile behavior (env-backed via LoadConfig).
type Config struct {
	ArduinoCLIPath string // default: "arduino-cli" from PATH
	// DataDir is ARDUINO_DIRECTORIES_DATA when non-empty. If empty, arduino-cli uses its
	// default (same as interactive CLI, e.g. ~/Library/Arduino15 on macOS). Set to isolate
	// cores/libs on servers (e.g. /var/lib/arduino-cli-data).
	DataDir        string
	SketchMaxBytes int
	CompileTimeout time.Duration
	CleanupAfter   time.Duration // extra delayed RemoveAll on work dir (safety net)
	// DockerImage, if set (e.g. from ARDUINO_DOCKER_IMAGE), runs arduino-cli inside that image
	// via docker run (see docker/arduino-compile/Dockerfile). Ignores ARDUINO_CLI / DataDir for compile.
	DockerImage  string
	DockerBinary string // container runtime: docker or podman (rootless/daemonless OK). Default: docker.
}

// LoadConfig reads optional env: ARDUINO_CLI, ARDUINO_COMPILE_DATA_DIR, ARDUINO_COMPILE_SKETCH_MAX_BYTES, ARDUINO_COMPILE_TIMEOUT_SEC.
func LoadConfig() *Config {
	c := &Config{
		ArduinoCLIPath: os.Getenv("ARDUINO_CLI"),
		SketchMaxBytes: defaultSketchMaxBytes,
		CompileTimeout: defaultCompileTimeout,
		CleanupAfter:   defaultCleanupAfter,
	}
	if c.ArduinoCLIPath == "" {
		c.ArduinoCLIPath = "arduino-cli"
	}
	c.DataDir = os.Getenv("ARDUINO_COMPILE_DATA_DIR")
	c.DockerImage = strings.TrimSpace(os.Getenv("ARDUINO_DOCKER_IMAGE"))
	c.DockerBinary = strings.TrimSpace(os.Getenv("ARDUINO_DOCKER_BINARY"))
	if c.DockerBinary == "" {
		c.DockerBinary = "docker"
	}
	if v := os.Getenv("ARDUINO_COMPILE_SKETCH_MAX_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.SketchMaxBytes = n
		}
	}
	if v := os.Getenv("ARDUINO_COMPILE_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.CompileTimeout = time.Duration(n) * time.Second
		}
	}
	return c
}

// arduinoCLIEnv returns the process environment for arduino-cli subprocesses.
// If cfg.DataDir is set, ARDUINO_DIRECTORIES_DATA is overridden; otherwise the CLI
// default is used (matches `arduino-cli core install` in your shell).
func arduinoCLIEnv(cfg *Config) []string {
	env := os.Environ()
	if cfg != nil && strings.TrimSpace(cfg.DataDir) != "" {
		env = append(env, "ARDUINO_DIRECTORIES_DATA="+cfg.DataDir)
	}
	return env
}

// Request is the compile API input.
// Provide the main sketch as "sketch" (sketch.ino) and optional additional files in Files
// (headers, .cpp, other .ino tabs). Alternatively omit "sketch" and include sketch.ino inside Files.
type Request struct {
	Sketch    string
	Files     []SketchFile
	Board     string
	Libraries []string
	JobStore  *JobStore // if set, ESP32 artifacts go to job store (returns jobId, not base64)
}

// ErrorDetail is a single compile diagnostic.
type ErrorDetail struct {
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
}

// Response matches POST /api/arduino-compile JSON shape.
// Successful compiles set outputFormat: AVR → hex; RP2040 → uf2; ESP32 → bin.
//
// For ESP32 boards, artifacts are stored on disk (not sent as base64) and referenced
// by JobID. The browser sends JobID to /api/arduino-simulate/start to boot QEMU.
// Bin/MergedBin are still populated for backward compatibility but are empty when
// JobID is set (avoids sending 4MB base64 over the wire).
type Response struct {
	Success       bool          `json:"success"`
	OutputFormat  string        `json:"outputFormat,omitempty"` // "hex" | "uf2" | "bin" when success
	Hex           string        `json:"hex,omitempty"`          // Intel HEX text when outputFormat is hex
	UF2           string        `json:"uf2,omitempty"`          // base64(UF2 file bytes) when outputFormat is uf2
	Bin           string        `json:"bin,omitempty"`          // base64(flashable .bin) — empty for ESP32 when JobID is set
	MergedBin     string        `json:"mergedBin,omitempty"`    // base64(merged.bin) — empty for ESP32 when JobID is set
	JobID         string        `json:"jobId,omitempty"`        // ESP32 only: reference for /api/arduino-simulate/start
	ProgramSize   int           `json:"programSize,omitempty"`
	MaxSize       int           `json:"maxSize,omitempty"`
	BuildOutput   string        `json:"buildOutput,omitempty"`
	Warnings      []string      `json:"warnings,omitempty"`
	CompileTimeMs int64         `json:"compileTimeMs,omitempty"`
	Error         string        `json:"error,omitempty"`   // "compile" | "validation"
	Message       string        `json:"message,omitempty"` // validation
	Errors        []ErrorDetail `json:"errors,omitempty"`
	RawOutput     string        `json:"rawOutput,omitempty"`
}

var (
	// Basename only: letters, digits, dot, underscore, hyphen; must have an extension.
	sketchBasenamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}\.[a-zA-Z0-9]+$`)
	fqbnPattern           = regexp.MustCompile(`^[a-zA-Z0-9_.:-]+$`)
	// Library names from Arduino registry may include spaces (e.g. "DHT sensor library").
	libNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.+\- ]{0,62}$`)
	// /tmp/.../sketch/sketch.ino:line:col: error: message
	errorLinePattern = regexp.MustCompile(`[^\s]+sketch\.ino:(\d+):(\d+):\s*(?:fatal\s+)?error:\s*(.+)$`)
	// Sketch uses 924 bytes (2%) of program storage space. Maximum is 32256 bytes.
	sketchUsePattern    = regexp.MustCompile(`Sketch uses\s+(\d+)\s+bytes\s+\([^)]+\)\s+of program storage space\.\s+Maximum is\s+(\d+)\s+bytes`)
	altSketchUsePattern = regexp.MustCompile(`Sketch uses\s+(\d+)\s+bytes`)
)

type sketchDiskFile struct {
	name string
	text string
}

// collectSketchFiles merges top-level sketch (sketch.ino) with optional Files. If sketch is empty,
// Files must include sketch.ino. Names must be basenames only (no path separators).
func collectSketchFiles(req *Request, maxBytes int) ([]sketchDiskFile, error) {
	if req == nil {
		return nil, fmt.Errorf("nil request")
	}
	var out []sketchDiskFile
	seen := make(map[string]struct{})

	if strings.TrimSpace(req.Sketch) != "" {
		if err := validateSketchSource(req.Sketch); err != nil {
			return nil, err
		}
		seen[strings.ToLower(mainSketchFile)] = struct{}{}
		out = append(out, sketchDiskFile{name: mainSketchFile, text: req.Sketch})
	}

	for _, f := range req.Files {
		name := strings.TrimSpace(f.Name)
		if name == "" {
			return nil, fmt.Errorf("empty file name in files")
		}
		bn := filepath.Base(name)
		if bn != name || strings.Contains(name, "..") {
			return nil, fmt.Errorf("invalid file name %q (use basename only, no paths)", f.Name)
		}
		if !sketchBasenamePattern.MatchString(bn) {
			return nil, fmt.Errorf("invalid file name %q", bn)
		}
		key := strings.ToLower(bn)
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("duplicate file %q", bn)
		}
		if strings.EqualFold(bn, mainSketchFile) && strings.TrimSpace(req.Sketch) != "" {
			return nil, fmt.Errorf("duplicate sketch.ino: use top-level \"sketch\" only, or omit it and put sketch.ino in \"files\"")
		}
		if err := validateSketchSource(f.Content); err != nil {
			return nil, err
		}
		seen[key] = struct{}{}
		out = append(out, sketchDiskFile{name: bn, text: f.Content})
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("sketch is required")
	}
	if _, ok := seen[strings.ToLower(mainSketchFile)]; !ok {
		return nil, fmt.Errorf("main sketch must be in \"sketch\" or include sketch.ino in \"files\"")
	}
	if len(out) > maxSketchFiles {
		return nil, fmt.Errorf("too many sketch files (max %d)", maxSketchFiles)
	}
	total := 0
	for _, f := range out {
		total += len(f.text)
	}
	if total > maxBytes {
		return nil, fmt.Errorf("sketch files exceed maximum size (%dKB limit)", maxBytes/1024)
	}
	return out, nil
}

// sketch.ino first, then other files sorted by name (Arduino merges multiple .ino alphabetically).
func sortSketchFilesForWrite(in []sketchDiskFile) []sketchDiskFile {
	var main *sketchDiskFile
	var rest []sketchDiskFile
	for i := range in {
		if strings.EqualFold(in[i].name, mainSketchFile) {
			v := in[i]
			main = &v
			continue
		}
		rest = append(rest, in[i])
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].name < rest[j].name })
	if main == nil {
		return in
	}
	out := []sketchDiskFile{*main}
	out = append(out, rest...)
	return out
}

// Compile validates input, writes a temp sketch, runs arduino-cli, removes the temp tree (plus delayed cleanup).
// Subprocesses use exec.Command with argv slices (no shell); user sketch is never passed on a shell command line.
// If cfg.DockerImage is set (ARDUINO_DOCKER_IMAGE), compilation runs via docker/podman (ARDUINO_DOCKER_BINARY)
// with --network none and the temp dir bind-mounted (see docker/arduino-compile/Dockerfile).
// Extra allowlisted libraries are installed first into sketch/libraries (outbound network).
func Compile(ctx context.Context, cfg *Config, req *Request) Response {
	if cfg == nil {
		cfg = LoadConfig()
	}
	filesToWrite, err := collectSketchFiles(req, cfg.SketchMaxBytes)
	if err != nil {
		return Response{Success: false, Error: "validation", Message: err.Error()}
	}
	board := strings.TrimSpace(req.Board)
	if board == "" {
		return Response{Success: false, Error: "validation", Message: "board is required"}
	}
	if !fqbnPattern.MatchString(board) {
		return Response{Success: false, Error: "validation", Message: "Invalid board FQBN format"}
	}
	if EnforceBoardAllowlist() && !boardAllowedByPolicy(board) {
		return Response{Success: false, Error: "validation", Message: fmt.Sprintf("board %q is not allowed; allowed FQBNs are configured via ARDUINO_SUPPORTED_BOARD_FQBNS", board)}
	}
	if len(req.Libraries) > maxLibraries {
		return Response{Success: false, Error: "validation", Message: fmt.Sprintf("Too many libraries (max %d)", maxLibraries)}
	}
	for _, lib := range req.Libraries {
		lib = strings.TrimSpace(lib)
		if lib == "" {
			return Response{Success: false, Error: "validation", Message: "Empty library name"}
		}
		if !libNamePattern.MatchString(strings.TrimSpace(lib)) {
			return Response{Success: false, Error: "validation", Message: fmt.Sprintf("Invalid library name: %q", lib)}
		}
	}

	if err := validateDataDir(cfg.DataDir); err != nil {
		return Response{Success: false, Error: "compile", RawOutput: err.Error()}
	}

	var cliPath string
	dockerMode := strings.TrimSpace(cfg.DockerImage) != ""
	if dockerMode {
		if err := validateDockerImageRef(cfg.DockerImage); err != nil {
			return Response{Success: false, Error: "validation", Message: err.Error()}
		}
		if err := validateLibrariesForDocker(req.Libraries); err != nil {
			return Response{Success: false, Error: "validation", Message: err.Error()}
		}
		if err := validateContainerRuntime(cfg); err != nil {
			return Response{Success: false, Error: "compile", RawOutput: err.Error()}
		}
	} else {
		var err error
		cliPath, err = exec.LookPath(cfg.ArduinoCLIPath)
		if err != nil {
			return Response{
				Success:   false,
				Error:     "compile",
				RawOutput: "arduino-cli not found in PATH (set ARDUINO_CLI)",
			}
		}
		if err := validateResolvedArduinoCLI(cliPath); err != nil {
			return Response{Success: false, Error: "compile", RawOutput: err.Error()}
		}
	}

	workDir, err := os.MkdirTemp("", "arduino-compile-*")
	if err != nil {
		return Response{Success: false, Error: "compile", RawOutput: err.Error()}
	}
	scheduleCleanup(workDir, cfg.CleanupAfter)

	sketchDir := filepath.Join(workDir, "sketch")
	if err := os.MkdirAll(sketchDir, 0o755); err != nil {
		_ = os.RemoveAll(workDir)
		return Response{Success: false, Error: "compile", RawOutput: err.Error()}
	}
	for _, f := range sortSketchFilesForWrite(filesToWrite) {
		p := filepath.Join(sketchDir, f.name)
		if err := os.WriteFile(p, []byte(f.text), 0o644); err != nil {
			_ = os.RemoveAll(workDir)
			return Response{Success: false, Error: "compile", RawOutput: err.Error()}
		}
	}

	// Inject QEMU GPIO bridge for ESP32 boards.
	// 1. Write _qemu_bridge.h (GPIO macro wrappers) into the sketch dir
	// 2. Prepend #include "_qemu_bridge.h" to sketch.ino so macros apply to user code
	if isESP32Board(board) {
		bridgePath := filepath.Join(sketchDir, qemuBridgeFilename)
		if err := os.WriteFile(bridgePath, []byte(qemuBridgeSource), 0o644); err != nil {
			_ = os.RemoveAll(workDir)
			return Response{Success: false, Error: "compile", RawOutput: "failed to write QEMU bridge: " + err.Error()}
		}
		// Prepend #include to sketch.ino
		sketchPath := filepath.Join(sketchDir, mainSketchFile)
		if orig, err := os.ReadFile(sketchPath); err == nil {
			patched := qemuBridgeSketchPrefix + string(orig)
			_ = os.WriteFile(sketchPath, []byte(patched), 0o644)
		}
	}

	outDir := filepath.Join(workDir, "build")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		_ = os.RemoveAll(workDir)
		return Response{Success: false, Error: "compile", RawOutput: err.Error()}
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.CompileTimeout)
	defer cancel()

	start := time.Now()

	var rawCombined string
	var runErr error

	if dockerMode {
		// Baked-in Dockerfile libs: skip. Allowlisted extras: one container run per lib (network) into sketch/libraries.
		for _, lib := range req.Libraries {
			lib = strings.TrimSpace(lib)
			canon, ok := dockerExtraInstallCanonical(lib)
			if !ok || canon == "" {
				continue
			}
			if err := runContainerLibInstall(ctx, cfg, workDir, canon); err != nil {
				_ = os.RemoveAll(workDir)
				return compileFailureResponseFromOutput(start, err.Error())
			}
		}
		rawCombined, runErr = runContainerCompile(ctx, cfg, workDir, board)
	} else {
		env := arduinoCLIEnv(cfg)
		if cfg.DataDir != "" {
			_ = os.MkdirAll(cfg.DataDir, 0o755)
		}

		for _, lib := range req.Libraries {
			lib = strings.TrimSpace(lib)
			install := exec.CommandContext(ctx, cliPath, "lib", "install", lib, "--no-color")
			install.Env = env
			var installOut bytes.Buffer
			install.Stdout = &installOut
			install.Stderr = &installOut
			if err := install.Run(); err != nil {
				raw := strings.TrimSpace(installOut.String())
				if raw == "" {
					raw = err.Error()
				}
				_ = os.RemoveAll(workDir)
				return compileFailureResponseFromOutput(start, raw)
			}
		}

		compileBoard := board
		esp32Mode := isESP32Board(board)
		// ESP32 boards: force DIO flash mode for QEMU compatibility.
		if esp32Mode && !strings.Contains(board, "FlashMode=") {
			compileBoard = board + ":FlashMode=dio"
		}
		compileArgs := []string{"compile",
			"-b", compileBoard,
			"--output-dir", outDir,
			"--warnings", "all",
			"--verbose",
		}
		// ESP32: add -include flag to inject GPIO/PWM bridge header
		if esp32Mode && qemuBridgeBuildFlag != "" {
			compileArgs = append(compileArgs, "--build-property", qemuBridgeBuildFlag)
		}
		compileArgs = append(compileArgs, sketchDir)
		compileCmd := exec.CommandContext(ctx, cliPath, compileArgs...)
		compileCmd.Env = env
		var compileOut bytes.Buffer
		compileCmd.Stdout = &compileOut
		compileCmd.Stderr = &compileOut
		runErr = compileCmd.Run()
		rawCombined = compileOut.String()
	}
	elapsed := time.Since(start).Milliseconds()

	if runErr != nil {
		_ = os.RemoveAll(workDir)
		return compileFailureResponseFromOutput(start, rawCombined)
	}

	artPath, artKind, aerr := findBuildArtifact(outDir)
	if aerr != nil {
		_ = os.RemoveAll(workDir)
		return Response{
			Success:       false,
			Error:         "compile",
			RawOutput:     rawCombined + "\n" + aerr.Error(),
			Errors:        parseErrors(rawCombined),
			CompileTimeMs: elapsed,
		}
	}
	artifactBytes, err := os.ReadFile(artPath)
	if err != nil {
		_ = os.RemoveAll(workDir)
		return Response{Success: false, Error: "compile", RawOutput: err.Error(), CompileTimeMs: elapsed}
	}

	programSize, maxSize := parseSketchSizes(rawCombined)
	warnings := extractWarnings(rawCombined)

	out := Response{
		Success:       true,
		OutputFormat:  artKind,
		ProgramSize:   programSize,
		MaxSize:       maxSize,
		BuildOutput:   trimBuildOutput(rawCombined),
		Warnings:      warnings,
		CompileTimeMs: elapsed,
	}

	// ESP32 with JobStore: keep artifacts on disk, return jobId (no base64 blobs).
	// The browser sends jobId to /api/arduino-simulate/start to boot QEMU.
	if isESP32Board(board) && req.JobStore != nil {
		jobID, jobDir, err := req.JobStore.CreateJob(board)
		if err == nil {
			// Copy build artifacts to job directory
			copyDir(outDir, filepath.Join(jobDir, "build"))
			out.JobID = jobID
			// Don't send bin/mergedBin — browser uses jobId instead
		}
		_ = os.RemoveAll(workDir)
		return out
	}

	// Non-ESP32 (or no JobStore): return artifacts as base64
	switch artKind {
	case "uf2":
		out.UF2 = base64.StdEncoding.EncodeToString(artifactBytes)
	case "hex":
		out.Hex = string(bytes.TrimSpace(artifactBytes))
	case "bin":
		out.Bin = base64.StdEncoding.EncodeToString(artifactBytes)
		// Also include merged.bin for ESP32 (backward compat when no JobStore)
		if isESP32Board(board) {
			if mp := findSketchMergedBin(outDir); mp != "" {
				if b, rerr := os.ReadFile(mp); rerr == nil && len(b) > 0 {
					out.MergedBin = base64.StdEncoding.EncodeToString(b)
				}
			}
		}
	default:
		_ = os.RemoveAll(workDir)
		return Response{Success: false, Error: "compile", RawOutput: "unknown artifact kind: " + artKind, CompileTimeMs: elapsed}
	}
	_ = os.RemoveAll(workDir)
	return out
}

// copyDir copies all files from src to dst (one level, not recursive).
func copyDir(src, dst string) {
	_ = os.MkdirAll(dst, 0o755)
	entries, err := os.ReadDir(src)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			continue
		}
		_ = os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644)
	}
}

func scheduleCleanup(path string, after time.Duration) {
	if after <= 0 {
		return
	}
	p := path
	time.AfterFunc(after, func() {
		_ = os.RemoveAll(p)
	})
}

func compileFailureResponseFromOutput(start time.Time, raw string) Response {
	elapsed := time.Since(start).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	errs := parseErrors(raw)
	return Response{
		Success:       false,
		Error:         "compile",
		Errors:        errs,
		RawOutput:     strings.TrimSpace(raw),
		CompileTimeMs: elapsed,
	}
}

// findBuildArtifact locates the main firmware file after compile.
// RP2040 → .uf2; AVR → .hex; ESP32 → .bin. Prefer sketch.ino.*; skip obvious bootloader artifacts.
func findBuildArtifact(outDir string) (path string, kind string, err error) {
	var uf2s, hexes, bins []string
	_ = filepath.Walk(outDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return nil
		}
		base := strings.ToLower(filepath.Base(path))
		if strings.Contains(base, "bootloader") {
			return nil
		}
		switch {
		case strings.HasSuffix(base, ".uf2"):
			uf2s = append(uf2s, path)
		case strings.HasSuffix(base, ".hex"):
			hexes = append(hexes, path)
		case strings.HasSuffix(base, ".bin"):
			bins = append(bins, path)
		}
		return nil
	})
	pickSketch := func(cands []string) string {
		for _, p := range cands {
			if strings.Contains(strings.ToLower(filepath.Base(p)), "sketch.ino") {
				return p
			}
		}
		if len(cands) > 0 {
			return cands[0]
		}
		return ""
	}
	if p := pickSketch(uf2s); p != "" {
		return p, "uf2", nil
	}
	if len(uf2s) > 0 {
		return uf2s[0], "uf2", nil
	}
	if p := pickSketch(hexes); p != "" {
		return p, "hex", nil
	}
	if len(hexes) > 0 {
		return hexes[0], "hex", nil
	}
	if p := pickSketch(bins); p != "" {
		return p, "bin", nil
	}
	if len(bins) > 0 {
		return bins[0], "bin", nil
	}
	return "", "", errors.New("no .hex, .uf2, or .bin file produced")
}

// IsESP32Board checks if a board FQBN is an ESP32 variant.
func IsESP32Board(board string) bool {
	return isESP32Board(board)
}

func isESP32Board(board string) bool {
	b := strings.TrimSpace(strings.ToLower(board))
	return strings.HasPrefix(b, "esp32:")
}

// findSketchMergedBin returns the path to sketch.ino.merged.bin under outDir (ESP32 all-in-one flash image), or "".
func findSketchMergedBin(outDir string) string {
	const want = "sketch.ino.merged.bin"
	var found string
	_ = filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Base(path), want) {
			found = path
			return fs.SkipAll
		}
		return nil
	})
	return found
}

func parseErrors(raw string) []ErrorDetail {
	var out []ErrorDetail
	lines := strings.Split(raw, "\n")
	var pending *ErrorDetail
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		if m := errorLinePattern.FindStringSubmatch(line); len(m) == 4 {
			lineNo, _ := strconv.Atoi(m[1])
			col, _ := strconv.Atoi(m[2])
			msg := strings.TrimSpace(m[3])
			d := ErrorDetail{Line: lineNo, Column: col, Message: msg}
			if strings.Contains(msg, "did you mean") {
				d.Suggestion = msg
			}
			out = append(out, d)
			pending = &out[len(out)-1]
			continue
		}
		// Suggestion line after caret block: "      |   digitalWrite"
		if pending != nil && strings.Contains(line, "|") && i > 0 {
			prev := lines[i-1]
			if strings.Contains(prev, "^") && strings.Contains(line, "digitalWrite") {
				s := strings.TrimSpace(line)
				s = strings.TrimPrefix(s, "|")
				s = strings.TrimSpace(s)
				if s != "" && pending.Suggestion == "" {
					pending.Suggestion = "Did you mean '" + strings.Fields(s)[0] + "'?"
				}
			}
		}
	}
	return out
}

func parseSketchSizes(raw string) (program, max int) {
	if m := sketchUsePattern.FindStringSubmatch(raw); len(m) == 3 {
		program, _ = strconv.Atoi(m[1])
		max, _ = strconv.Atoi(m[2])
		return program, max
	}
	if m := altSketchUsePattern.FindStringSubmatch(raw); len(m) == 2 {
		program, _ = strconv.Atoi(m[1])
	}
	return program, max
}

func extractWarnings(raw string) []string {
	var w []string
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, "warning:") && strings.Contains(line, "sketch") {
			w = append(w, strings.TrimSpace(line))
		}
	}
	return w
}

func trimBuildOutput(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 20000 {
		s = s[:20000] + "\n... (truncated)"
	}
	// Strip control characters (except \n, \r, \t) that break JSON encoding.
	// The GPIO bridge header injects SOH (0x01) markers; verbose build output may include them.
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 32 || r == '\n' || r == '\r' || r == '\t' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
