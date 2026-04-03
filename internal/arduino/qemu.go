// Package arduino — QEMU ESP32 emulation manager.
//
// Manages qemu-system-riscv32 / qemu-system-xtensa processes for interactive
// ESP32 simulation. Each instance gets:
//   - QEMU process with firmware loaded as MTD flash
//   - UART0 bridged to a TCP port (serial I/O)
//   - Events sent/received via callback (for WebSocket/SSE bridging)
//
// Two modes:
//
//	Host mode:   QEMU binary on PATH (QEMU_RISCV32_BINARY / QEMU_XTENSA_BINARY)
//	Docker mode: QEMU_DOCKER_IMAGE set (e.g. "qemu-esp32:local")
//	             Runs QEMU inside the container, serial connects via host networking.
//
// Board → QEMU mapping:
//
//	esp32:esp32:esp32c3  → qemu-system-riscv32 -machine esp32c3
//	esp32:esp32:esp32    → qemu-system-xtensa  -machine esp32
//	esp32:esp32:esp32s3  → qemu-system-xtensa  -machine esp32s3
package arduino

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// QemuConfig configures the QEMU emulation service.
type QemuConfig struct {
	// Docker image for QEMU (e.g. "qemu-esp32:local"). If set, QEMU runs
	// inside this container. Binary paths are ignored in Docker mode.
	DockerImage string

	// Container runtime: "docker" or "podman". Default: "docker".
	DockerBinary string

	// Path to qemu-system-riscv32 binary (host mode, ESP32-C3).
	RiscV32Binary string

	// Path to qemu-system-xtensa binary (host mode, ESP32/ESP32-S3).
	XtensaBinary string

	// Max concurrent QEMU instances (0 = unlimited).
	MaxInstances int

	// Timeout for a QEMU instance (auto-kill). Default: 10 minutes.
	InstanceTimeout time.Duration

	// How often to sweep for stale instances. Default: 60 seconds.
	SweepInterval time.Duration
}

// LoadQemuConfig reads QEMU configuration from environment.
//
// Environment:
//
//	QEMU_DOCKER_IMAGE     — run QEMU inside this Docker image (e.g. qemu-esp32:local)
//	QEMU_DOCKER_BINARY    — docker or podman (default: docker)
//	QEMU_RISCV32_BINARY   — host path to qemu-system-riscv32
//	QEMU_XTENSA_BINARY    — host path to qemu-system-xtensa
//	QEMU_MAX_INSTANCES    — max concurrent QEMU processes (default: 20)
//	QEMU_INSTANCE_TIMEOUT — per-instance timeout in seconds (default: 600 = 10 min)
func LoadQemuConfig() *QemuConfig {
	maxInst := 20
	if v := os.Getenv("QEMU_MAX_INSTANCES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxInst = n
		}
	}
	timeout := 10 * time.Minute
	if v := os.Getenv("QEMU_INSTANCE_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			timeout = time.Duration(n) * time.Second
		}
	}
	sweep := 60 * time.Second
	if v := os.Getenv("QEMU_SWEEP_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sweep = time.Duration(n) * time.Second
		}
	}
	c := &QemuConfig{
		DockerImage:     strings.TrimSpace(os.Getenv("QEMU_DOCKER_IMAGE")),
		DockerBinary:    strings.TrimSpace(os.Getenv("QEMU_DOCKER_BINARY")),
		RiscV32Binary:   os.Getenv("QEMU_RISCV32_BINARY"),
		XtensaBinary:    os.Getenv("QEMU_XTENSA_BINARY"),
		MaxInstances:    maxInst,
		InstanceTimeout: timeout,
		SweepInterval:   sweep,
	}
	if c.DockerBinary == "" {
		c.DockerBinary = "docker"
	}
	if c.RiscV32Binary == "" {
		c.RiscV32Binary = "qemu-system-riscv32"
	}
	if c.XtensaBinary == "" {
		c.XtensaBinary = "qemu-system-xtensa"
	}
	return c
}

func (cfg *QemuConfig) isDockerMode() bool {
	return cfg.DockerImage != ""
}

// qemuBoardInfo maps board FQBN to QEMU binary + machine name.
type qemuBoardInfo struct {
	binary  string // qemu-system-riscv32 or qemu-system-xtensa
	machine string // esp32c3, esp32, esp32s3
}

func (cfg *QemuConfig) boardInfo(fqbn string) (qemuBoardInfo, error) {
	fqbn = strings.ToLower(strings.TrimSpace(fqbn))
	switch {
	case strings.Contains(fqbn, "esp32c3"):
		return qemuBoardInfo{binary: cfg.RiscV32Binary, machine: "esp32c3"}, nil
	case strings.Contains(fqbn, "esp32s3"):
		return qemuBoardInfo{binary: cfg.XtensaBinary, machine: "esp32s3"}, nil
	case strings.HasPrefix(fqbn, "esp32:"):
		return qemuBoardInfo{binary: cfg.XtensaBinary, machine: "esp32"}, nil
	default:
		return qemuBoardInfo{}, fmt.Errorf("board %q is not an ESP32 board (QEMU not applicable)", fqbn)
	}
}

// QemuEvent is sent from a QEMU instance to the API layer.
type QemuEvent struct {
	Type string      `json:"type"` // "serial_output", "gpio_change", "system"
	Data interface{} `json:"data"`
}

// QemuInstance represents a running QEMU process for one board.
type QemuInstance struct {
	ID      string
	Board   string
	Machine string
	OnEvent func(QemuEvent)

	mu         sync.Mutex
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	fwPath     string
	ownFile    bool
	serialPort int
	serialConn net.Conn
	running    bool
	startedAt  time.Time
}

// QemuManager manages QEMU instances.
type QemuManager struct {
	cfg       *QemuConfig
	mu        sync.Mutex
	instances map[string]*QemuInstance
	done      chan struct{}
}

// NewQemuManager creates a new manager. Kills orphaned containers on startup
// and starts a periodic sweep to kill instances that exceed their timeout.
func NewQemuManager(cfg *QemuConfig) *QemuManager {
	if cfg == nil {
		cfg = LoadQemuConfig()
	}
	m := &QemuManager{
		cfg:       cfg,
		instances: make(map[string]*QemuInstance),
		done:      make(chan struct{}),
	}
	if cfg.isDockerMode() {
		go m.cleanupOrphanContainers()
	}
	go m.sweepLoop()
	return m
}

func findFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port, nil
}

// StartInstance starts a QEMU instance for the given board with base64 firmware.
// For job-based flow, use StartFromFile instead.
func (m *QemuManager) StartInstance(ctx context.Context, id, board, firmwareB64 string, onEvent func(QemuEvent)) error {
	fwBytes, err := base64.StdEncoding.DecodeString(firmwareB64)
	if err != nil {
		return fmt.Errorf("invalid firmware base64: %w", err)
	}
	fwFile, err := os.CreateTemp("", "qemu-fw-*.bin")
	if err != nil {
		return fmt.Errorf("creating temp firmware file: %w", err)
	}
	if _, err := fwFile.Write(fwBytes); err != nil {
		fwFile.Close()
		os.Remove(fwFile.Name())
		return fmt.Errorf("writing firmware: %w", err)
	}
	fwFile.Close()
	return m.startWithFile(ctx, id, board, fwFile.Name(), true, onEvent)
}

// StartFromFile starts a QEMU instance using a firmware file already on disk.
// The file is NOT deleted on stop (caller owns it, e.g. JobStore).
func (m *QemuManager) StartFromFile(ctx context.Context, id, board, fwPath string, onEvent func(QemuEvent)) error {
	if _, err := os.Stat(fwPath); err != nil {
		return fmt.Errorf("firmware file not found: %w", err)
	}
	return m.startWithFile(ctx, id, board, fwPath, false, onEvent)
}

func (m *QemuManager) startWithFile(ctx context.Context, id, board, fwPath string, ownFile bool, onEvent func(QemuEvent)) error {
	info, err := m.cfg.boardInfo(board)
	if err != nil {
		return err
	}

	// Find free TCP port for serial
	serialPort, err := findFreePort()
	if err != nil {
		return fmt.Errorf("finding free port: %w", err)
	}

	// Use Background context — QEMU must outlive the HTTP request that started it.
	// The request context (ctx) is only used for validation, not for the QEMU process lifetime.
	qctx, cancel := context.WithTimeout(context.Background(), m.cfg.InstanceTimeout)

	// Build command: Docker mode vs host mode
	var cmd *exec.Cmd
	if m.cfg.isDockerMode() {
		cmd, err = m.buildDockerCmd(qctx, info, fwPath, serialPort, id)
	} else {
		cmd, err = m.buildHostCmd(qctx, info, fwPath, serialPort)
	}
	if err != nil {
		cancel()
		return err
	}

	inst := &QemuInstance{
		ID:         id,
		Board:      board,
		Machine:    info.machine,
		OnEvent:    onEvent,
		cmd:        cmd,
		cancel:     cancel,
		fwPath:     fwPath,
		ownFile:    ownFile,
		serialPort: serialPort,
		running:    true,
		startedAt:  time.Now(),
	}

	// Store instance
	m.mu.Lock()
	if m.cfg.MaxInstances > 0 && len(m.instances) >= m.cfg.MaxInstances {
		m.mu.Unlock()
		cancel()
		return fmt.Errorf("max QEMU instances reached (%d)", m.cfg.MaxInstances)
	}
	if old, ok := m.instances[id]; ok {
		m.mu.Unlock()
		m.StopInstance(old.ID)
		m.mu.Lock()
	}
	m.instances[id] = inst
	m.mu.Unlock()

	// Start process
	if err := cmd.Start(); err != nil {
		m.removeInstance(id)
		return fmt.Errorf("starting QEMU: %w", err)
	}

	if onEvent != nil {
		onEvent(QemuEvent{Type: "system", Data: map[string]string{
			"event":   "booting",
			"machine": info.machine,
			"mode":    m.modeString(),
		}})
	}

	// Connect to serial port and stream events
	go m.serialLoop(inst)

	return nil
}

// buildHostCmd creates an exec.Cmd that runs QEMU directly on the host.
func (m *QemuManager) buildHostCmd(ctx context.Context, info qemuBoardInfo, fwPath string, serialPort int) (*exec.Cmd, error) {
	qemuPath, err := exec.LookPath(info.binary)
	if err != nil {
		return nil, fmt.Errorf("QEMU binary %q not found: %w (install Espressif QEMU or set QEMU_RISCV32_BINARY)", info.binary, err)
	}

	args := []string{
		"-machine", info.machine,
		"-nographic",
		"-drive", fmt.Sprintf("file=%s,if=mtd,format=raw", fwPath),
		"-serial", fmt.Sprintf("tcp:127.0.0.1:%d,server=on,wait=off", serialPort),
		"-no-reboot",
	}

	cmd := exec.CommandContext(ctx, qemuPath, args...)
	cmd.Dir = filepath.Dir(fwPath)
	return cmd, nil
}

// buildDockerCmd creates an exec.Cmd that runs QEMU inside a Docker container.
// The firmware file is bind-mounted. Serial is exposed via -p port mapping so
// the Go process can connect to 127.0.0.1:PORT on the host.
//
// On macOS, --net=host doesn't work (Docker Desktop uses a VM), so we use
// -p PORT:PORT and QEMU binds to 0.0.0.0 inside the container.
func (m *QemuManager) buildDockerCmd(ctx context.Context, info qemuBoardInfo, fwPath string, serialPort int, id string) (*exec.Cmd, error) {
	rt, err := exec.LookPath(m.cfg.DockerBinary)
	if err != nil {
		return nil, fmt.Errorf("container runtime %q not found: %w", m.cfg.DockerBinary, err)
	}

	absFw, err := filepath.Abs(fwPath)
	if err != nil {
		return nil, err
	}

	qemuBin := info.binary
	containerName := "qemu-" + id

	fwDir := filepath.Dir(absFw)
	fwName := filepath.Base(absFw)

	args := []string{
		"run", "--rm",
		"--name", containerName,
		"--stop-timeout", "3",
		"-p", fmt.Sprintf("127.0.0.1:%d:%d", serialPort, serialPort),
		"-v", fwDir + ":/fwdir",
		m.cfg.DockerImage,
		"sh", "-c",
		fmt.Sprintf("cp /fwdir/%s /tmp/fw.bin && %s -machine %s -nographic -drive file=/tmp/fw.bin,if=mtd,format=raw -serial tcp:0.0.0.0:%d,server=on,wait=off -no-reboot",
			fwName, qemuBin, info.machine, serialPort),
	}

	cmd := exec.CommandContext(ctx, rt, args...)
	return cmd, nil
}

func (m *QemuManager) modeString() string {
	if m.cfg.isDockerMode() {
		return "docker:" + m.cfg.DockerImage
	}
	return "host"
}

// serialLoop connects to the QEMU serial TCP port and streams events.
func (m *QemuManager) serialLoop(inst *QemuInstance) {
	defer func() {
		m.removeInstance(inst.ID)
		if inst.OnEvent != nil {
			inst.OnEvent(QemuEvent{Type: "system", Data: map[string]string{"event": "exited"}})
		}
	}()

	// Wait for QEMU to start listening on the serial port.
	// Docker mode needs more time (container startup + QEMU boot).
	var conn net.Conn
	var err error
	for i := 0; i < 60; i++ {
		time.Sleep(200 * time.Millisecond)
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", inst.serialPort), time.Second)
		if err == nil {
			break
		}
	}
	if conn == nil {
		if inst.OnEvent != nil {
			inst.OnEvent(QemuEvent{Type: "error", Data: map[string]string{"message": "Failed to connect to QEMU serial port"}})
		}
		inst.cancel()
		inst.cmd.Wait()
		return
	}

	inst.mu.Lock()
	inst.serialConn = conn
	inst.mu.Unlock()

	if inst.OnEvent != nil {
		inst.OnEvent(QemuEvent{Type: "system", Data: map[string]string{"event": "booted"}})
	}

	// ESP32 boot milestones — emit system events so UI can show progress
	esp32Milestones := map[string]string{
		"rst:":     "boot_reset",
		"load:":    "boot_loading",
		"entry 0x": "boot_entry",
		"setup()":  "boot_setup",
	}
	emitted := make(map[string]bool)
	var bootBuf string

	// Read serial output, split bridge messages (\x01Gpin:val\n) from user serial
	var lineBuf []byte
	buf := make([]byte, 256)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		if n <= 0 || inst.OnEvent == nil {
			continue
		}

		// Parse byte stream: bridge messages start with \x01, user data is everything else
		var userChunk []byte
		for i := 0; i < n; i++ {
			b := buf[i]
			if b == 0x01 {
				// Flush any pending user data
				if len(userChunk) > 0 {
					inst.OnEvent(QemuEvent{
						Type: "serial_output",
						Data: map[string]interface{}{"data": string(userChunk), "uart": 0},
					})
					userChunk = nil
				}
				// Accumulate bridge line until \n
				lineBuf = lineBuf[:0]
				for i++; i < n && buf[i] != '\n'; i++ {
					lineBuf = append(lineBuf, buf[i])
				}
				parseBridgeMessage(inst, string(lineBuf))
			} else {
				userChunk = append(userChunk, b)
			}
		}
		// Flush remaining user data
		if len(userChunk) > 0 {
			chunk := string(userChunk)
			inst.OnEvent(QemuEvent{
				Type: "serial_output",
				Data: map[string]interface{}{"data": chunk, "uart": 0},
			})

			// Check ESP32 boot milestones
			bootBuf += chunk
			for keyword, event := range esp32Milestones {
				if !emitted[event] && strings.Contains(bootBuf, keyword) {
					emitted[event] = true
					inst.OnEvent(QemuEvent{
						Type: "system",
						Data: map[string]string{"event": event},
					})
				}
			}
			if len(bootBuf) > 2048 {
				bootBuf = bootBuf[len(bootBuf)-1024:]
			}
		}
	}

	inst.cmd.Wait()
}

// parseBridgeMessage handles structured messages from the injected GPIO bridge.
// Format: "G<pin>:<0|1>" for GPIO, "P<pin>:<duty>" for PWM.
func parseBridgeMessage(inst *QemuInstance, msg string) {
	if len(msg) < 3 || inst.OnEvent == nil {
		return
	}
	switch msg[0] {
	case 'G': // GPIO: G8:1
		parts := strings.SplitN(msg[1:], ":", 2)
		if len(parts) != 2 {
			return
		}
		pin := 0
		state := 0
		if _, err := fmt.Sscanf(parts[0], "%d", &pin); err != nil {
			return
		}
		if _, err := fmt.Sscanf(parts[1], "%d", &state); err != nil {
			return
		}
		inst.OnEvent(QemuEvent{
			Type: "gpio_change",
			Data: map[string]interface{}{"pin": pin, "state": state},
		})
	case 'P': // PWM: P9:128
		parts := strings.SplitN(msg[1:], ":", 2)
		if len(parts) != 2 {
			return
		}
		pin := 0
		duty := 0
		if _, err := fmt.Sscanf(parts[0], "%d", &pin); err != nil {
			return
		}
		if _, err := fmt.Sscanf(parts[1], "%d", &duty); err != nil {
			return
		}
		inst.OnEvent(QemuEvent{
			Type: "pwm_change",
			Data: map[string]interface{}{"pin": pin, "duty": duty},
		})
	}
}

// SendSerial writes bytes to the QEMU instance's UART0.
func (m *QemuManager) SendSerial(id string, data []byte) error {
	m.mu.Lock()
	inst, ok := m.instances[id]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("instance %q not found", id)
	}

	inst.mu.Lock()
	conn := inst.serialConn
	inst.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("serial not connected for instance %q", id)
	}

	_, err := conn.Write(data)
	return err
}

// StopInstance stops a QEMU instance. In Docker mode, also stops the named container.
func (m *QemuManager) StopInstance(id string) {
	m.mu.Lock()
	inst, ok := m.instances[id]
	m.mu.Unlock()
	if !ok {
		return
	}

	inst.mu.Lock()
	if inst.serialConn != nil {
		inst.serialConn.Close()
	}
	inst.cancel()
	inst.running = false
	inst.mu.Unlock()

	done := make(chan struct{})
	go func() {
		if inst.cmd.Process != nil {
			inst.cmd.Process.Kill()
			inst.cmd.Wait()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}

	// Docker: force-stop the named container in case process kill wasn't enough
	if m.cfg.isDockerMode() {
		containerName := "qemu-" + id
		exec.Command(m.cfg.DockerBinary, "stop", "-t", "1", containerName).Run()
		exec.Command(m.cfg.DockerBinary, "rm", "-f", containerName).Run()
	}

	m.removeInstance(id)
}

// sweepLoop periodically kills instances that exceed InstanceTimeout.
func (m *QemuManager) sweepLoop() {
	ticker := time.NewTicker(m.cfg.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.sweep()
		}
	}
}

func (m *QemuManager) sweep() {
	now := time.Now()
	var stale []string
	m.mu.Lock()
	for id, inst := range m.instances {
		if now.Sub(inst.startedAt) > m.cfg.InstanceTimeout {
			stale = append(stale, id)
		}
	}
	m.mu.Unlock()
	for _, id := range stale {
		m.StopInstance(id)
	}
}

// Shutdown stops all instances and the sweep goroutine.
func (m *QemuManager) Shutdown() {
	close(m.done)
	m.StopAll()
}

// cleanupOrphanContainers kills any leftover qemu-* containers from a previous crash.
func (m *QemuManager) cleanupOrphanContainers() {
	rt := m.cfg.DockerBinary
	out, err := exec.Command(rt, "ps", "-a", "--filter", "name=qemu-", "--format", "{{.Names}}").Output()
	if err != nil {
		return
	}
	for _, name := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		exec.Command(rt, "stop", "-t", "1", name).Run()
		exec.Command(rt, "rm", "-f", name).Run()
	}
}

func (m *QemuManager) removeInstance(id string) {
	m.mu.Lock()
	inst, ok := m.instances[id]
	delete(m.instances, id)
	m.mu.Unlock()

	if ok && inst.fwPath != "" && inst.ownFile {
		os.Remove(inst.fwPath)
	}
}

// StopAll stops all running instances.
func (m *QemuManager) StopAll() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.instances))
	for id := range m.instances {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	for _, id := range ids {
		m.StopInstance(id)
	}
}

// InstanceCount returns the number of running instances.
func (m *QemuManager) InstanceCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.instances)
}

// IsRunning checks if an instance is running.
func (m *QemuManager) IsRunning(id string) bool {
	m.mu.Lock()
	_, ok := m.instances[id]
	m.mu.Unlock()
	return ok
}
