package arduino

import (
	"context"
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

// PiConfig configures the Raspberry Pi 3 QEMU service.
type PiConfig struct {
	// QEMU binary for aarch64 (default: qemu-system-aarch64)
	QemuBinary string

	// Path to kernel8.img (64-bit ARM kernel for raspi3b)
	KernelPath string

	// Path to device tree blob (bcm2710-rpi-3-b.dtb)
	DTBPath string

	// Path to base SD card image (Raspberry Pi OS, ~2GB raw or qcow2)
	SDImagePath string

	// Docker image for QEMU (alternative to host binaries)
	DockerImage  string
	DockerBinary string

	// Max concurrent Pi instances
	MaxInstances int

	// Instance timeout (default: 30 minutes — Pi boots slower and runs longer)
	InstanceTimeout time.Duration

	// How often to sweep for stale instances. Default: 60 seconds.
	SweepInterval time.Duration

	// Overlay dir for qcow2 overlays (default: system temp)
	OverlayDir string
}

// LoadPiConfig reads Pi QEMU configuration from environment.
//
// Environment:
//
//	QEMU_AARCH64_BINARY   — path to qemu-system-aarch64 (default: qemu-system-aarch64)
//	PI_KERNEL_PATH        — path to kernel8.img
//	PI_DTB_PATH           — path to bcm2710-rpi-3-b.dtb
//	PI_SD_IMAGE_PATH      — path to base Raspberry Pi OS image
//	PI_QEMU_DOCKER_IMAGE  — Docker image with qemu-system-aarch64 + boot files
//	PI_MAX_INSTANCES      — max concurrent Pi instances (default: 5)
//	PI_INSTANCE_TIMEOUT   — per-instance timeout in seconds (default: 1800 = 30 min)
//	PI_OVERLAY_DIR        — directory for qcow2 overlays (default: system temp)
func LoadPiConfig() *PiConfig {
	maxInst := 5
	if v := os.Getenv("PI_MAX_INSTANCES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxInst = n
		}
	}
	timeout := 30 * time.Minute
	if v := os.Getenv("PI_INSTANCE_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			timeout = time.Duration(n) * time.Second
		}
	}

	sweep := 60 * time.Second
	if v := os.Getenv("PI_SWEEP_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sweep = time.Duration(n) * time.Second
		}
	}
	c := &PiConfig{
		QemuBinary:      envOrDefault("QEMU_AARCH64_BINARY", "qemu-system-aarch64"),
		KernelPath:      os.Getenv("PI_KERNEL_PATH"),
		DTBPath:         os.Getenv("PI_DTB_PATH"),
		SDImagePath:     os.Getenv("PI_SD_IMAGE_PATH"),
		DockerImage:     strings.TrimSpace(os.Getenv("PI_QEMU_DOCKER_IMAGE")),
		DockerBinary:    envOrDefault("PI_QEMU_DOCKER_BINARY", "docker"),
		MaxInstances:    maxInst,
		InstanceTimeout: timeout,
		SweepInterval:   sweep,
		OverlayDir:      os.Getenv("PI_OVERLAY_DIR"),
	}
	return c
}

func envOrDefault(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

// PiInstance represents a running Raspberry Pi QEMU process.
type PiInstance struct {
	ID string

	mu          sync.Mutex
	cmd         *exec.Cmd
	cancel      context.CancelFunc
	overlayPath string
	serialPort  int
	gpioPort    int
	serialConn  net.Conn
	gpioConn    net.Conn
	running     bool
	startedAt   time.Time
	OnEvent     func(QemuEvent)
}

// PiManager manages Raspberry Pi QEMU instances.
type PiManager struct {
	cfg       *PiConfig
	mu        sync.Mutex
	instances map[string]*PiInstance
	done      chan struct{}
}

// NewPiManager creates a new Pi manager with periodic sweep.
func NewPiManager(cfg *PiConfig) *PiManager {
	if cfg == nil {
		cfg = LoadPiConfig()
	}
	m := &PiManager{
		cfg:       cfg,
		instances: make(map[string]*PiInstance),
		done:      make(chan struct{}),
	}
	if cfg.DockerImage != "" {
		go m.cleanupOrphanContainers()
	}
	go m.sweepLoop()
	return m
}

// CheckPrerequisites verifies that QEMU and boot files are available.
func (m *PiManager) CheckPrerequisites() error {
	if m.cfg.DockerImage != "" {
		return nil // Docker mode — files are inside the image
	}
	if _, err := exec.LookPath(m.cfg.QemuBinary); err != nil {
		return fmt.Errorf("qemu-system-aarch64 not found: %w (set QEMU_AARCH64_BINARY)", err)
	}
	if _, err := exec.LookPath("qemu-img"); err != nil {
		return fmt.Errorf("qemu-img not found: %w (needed for overlay creation)", err)
	}
	for _, f := range []struct{ path, env, desc string }{
		{m.cfg.KernelPath, "PI_KERNEL_PATH", "kernel8.img"},
		{m.cfg.DTBPath, "PI_DTB_PATH", "bcm2710-rpi-3-b.dtb"},
		{m.cfg.SDImagePath, "PI_SD_IMAGE_PATH", "Raspberry Pi OS SD image"},
	} {
		if f.path == "" {
			return fmt.Errorf("%s not set (set %s)", f.desc, f.env)
		}
		if _, err := os.Stat(f.path); err != nil {
			return fmt.Errorf("%s not found at %q: %w", f.desc, f.path, err)
		}
	}
	return nil
}

// StartInstance boots a Pi 3 QEMU instance.
// In Docker mode, the container handles overlay creation and boot via boot.sh.
// In host mode, we create the overlay and spawn QEMU directly.
func (m *PiManager) StartInstance(ctx context.Context, id string, onEvent func(QemuEvent)) error {
	isDocker := m.cfg.DockerImage != ""
	if !isDocker {
		if err := m.CheckPrerequisites(); err != nil {
			return err
		}
	}

	m.mu.Lock()
	if m.cfg.MaxInstances > 0 && len(m.instances) >= m.cfg.MaxInstances {
		m.mu.Unlock()
		return fmt.Errorf("max Pi instances reached (%d)", m.cfg.MaxInstances)
	}
	if old, ok := m.instances[id]; ok {
		m.mu.Unlock()
		m.StopInstance(old.ID)
		m.mu.Lock()
	}
	m.mu.Unlock()

	serialPort, err := findFreePort()
	if err != nil {
		return fmt.Errorf("finding serial port: %w", err)
	}
	gpioPort, err := findFreePort()
	if err != nil {
		return fmt.Errorf("finding gpio port: %w", err)
	}

	qctx, cancel := context.WithTimeout(context.Background(), m.cfg.InstanceTimeout)
	var cmd *exec.Cmd
	var overlayPath string

	if isDocker {
		// Docker mode: container handles everything — just map ports
		rt, err := exec.LookPath(m.cfg.DockerBinary)
		if err != nil {
			cancel()
			return fmt.Errorf("container runtime %q not found: %w", m.cfg.DockerBinary, err)
		}
		cmd = exec.CommandContext(qctx, rt,
			"run", "--rm",
			"--name", "pi-"+id,
			"--stop-timeout", "5",
			"-p", fmt.Sprintf("127.0.0.1:%d:%d", serialPort, serialPort),
			"-p", fmt.Sprintf("127.0.0.1:%d:%d", gpioPort, gpioPort),
			m.cfg.DockerImage,
			"/opt/pi/boot.sh",
			fmt.Sprintf("%d", serialPort),
			fmt.Sprintf("%d", gpioPort),
		)
	} else {
		// Host mode: create overlay and spawn QEMU directly
		overlayDir := m.cfg.OverlayDir
		if overlayDir == "" {
			overlayDir = os.TempDir()
		}
		overlayFile, err := os.CreateTemp(overlayDir, "pi-overlay-*.qcow2")
		if err != nil {
			cancel()
			return fmt.Errorf("creating overlay file: %w", err)
		}
		overlayFile.Close()
		overlayPath = overlayFile.Name()

		absSD, _ := filepath.Abs(m.cfg.SDImagePath)
		imgCmd := exec.Command("qemu-img", "create", "-f", "qcow2",
			"-b", absSD, "-F", "raw", overlayPath)
		if out, err := imgCmd.CombinedOutput(); err != nil {
			os.Remove(overlayPath)
			cancel()
			return fmt.Errorf("qemu-img create failed: %s\n%w", out, err)
		}
		resizeCmd := exec.Command("qemu-img", "resize", overlayPath, "8G")
		if out, err := resizeCmd.CombinedOutput(); err != nil {
			os.Remove(overlayPath)
			cancel()
			return fmt.Errorf("qemu-img resize failed: %s\n%w", out, err)
		}

		absKernel, _ := filepath.Abs(m.cfg.KernelPath)
		absDTB, _ := filepath.Abs(m.cfg.DTBPath)
		qemuPath, err := exec.LookPath(m.cfg.QemuBinary)
		if err != nil {
			cancel()
			os.Remove(overlayPath)
			return fmt.Errorf("qemu-system-aarch64 not found: %w", err)
		}

		cmd = exec.CommandContext(qctx, qemuPath,
			"-M", "raspi3b",
			"-kernel", absKernel,
			"-dtb", absDTB,
			"-drive", fmt.Sprintf("file=%s,if=sd,format=qcow2", overlayPath),
			"-m", "1G", "-smp", "4",
			"-display", "none",
			"-chardev", fmt.Sprintf("socket,id=serial0,host=127.0.0.1,port=%d,server=on,wait=off", serialPort),
			"-serial", "chardev:serial0",
			"-chardev", fmt.Sprintf("socket,id=serial1,host=127.0.0.1,port=%d,server=on,wait=off", gpioPort),
			"-serial", "chardev:serial1",
			"-monitor", "none",
			"-append", "console=ttyAMA0 earlycon=pl011,0x3f201000 root=/dev/mmcblk0p2 rootwait rw dwc_otg.lpm_enable=0",
		)
	}

	inst := &PiInstance{
		ID:          id,
		cmd:         cmd,
		cancel:      cancel,
		overlayPath: overlayPath,
		serialPort:  serialPort,
		gpioPort:    gpioPort,
		running:     true,
		startedAt:   time.Now(),
		OnEvent:     onEvent,
	}

	m.mu.Lock()
	m.instances[id] = inst
	m.mu.Unlock()

	if err := cmd.Start(); err != nil {
		m.removeInstance(id)
		return fmt.Errorf("starting Pi QEMU: %w", err)
	}

	if onEvent != nil {
		onEvent(QemuEvent{Type: "system", Data: map[string]string{"event": "booting", "machine": "raspi3b"}})
	}

	// Connect serial and GPIO in background
	go m.piSerialLoop(inst)
	go m.piGPIOLoop(inst)

	return nil
}

// piSerialLoop connects to ttyAMA0 and streams terminal I/O.
func (m *PiManager) piSerialLoop(inst *PiInstance) {
	defer func() {
		m.removeInstance(inst.ID)
		if inst.OnEvent != nil {
			inst.OnEvent(QemuEvent{Type: "system", Data: map[string]string{"event": "exited"}})
		}
	}()

	var conn net.Conn
	var err error
	for i := 0; i < 120; i++ { // Pi boots slower — wait up to 24s
		time.Sleep(200 * time.Millisecond)
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", inst.serialPort), time.Second)
		if err == nil {
			break
		}
	}
	if conn == nil {
		if inst.OnEvent != nil {
			inst.OnEvent(QemuEvent{Type: "error", Data: map[string]string{"message": "Failed to connect to Pi serial port"}})
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

	// Track boot progress — emit milestone events so the UI can show status
	var bootBuf string
	milestones := map[string]string{
		"Booting Linux":   "boot_kernel",
		"SMP:":            "boot_smp",
		"NET: Registered": "boot_network",
		"mmcblk0":         "boot_sdcard",
		"EXT4-fs":         "boot_filesystem",
		"systemd":         "boot_systemd",
		"login:":          "boot_login",
		"raspberrypi":     "boot_ready",
	}
	emitted := make(map[string]bool)

	buf := make([]byte, 512)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		if n > 0 && inst.OnEvent != nil {
			chunk := string(buf[:n])
			inst.OnEvent(QemuEvent{
				Type: "serial_output",
				Data: map[string]interface{}{"data": chunk, "uart": 0},
			})

			// Check for boot milestones
			bootBuf += chunk
			for keyword, event := range milestones {
				if !emitted[event] && strings.Contains(bootBuf, keyword) {
					emitted[event] = true
					inst.OnEvent(QemuEvent{
						Type: "system",
						Data: map[string]string{"event": event},
					})
				}
			}
			// Keep bootBuf from growing unbounded
			if len(bootBuf) > 4096 {
				bootBuf = bootBuf[len(bootBuf)-2048:]
			}
		}
	}
	inst.cmd.Wait()
}

// piGPIOLoop connects to ttyAMA1 and handles GPIO shim protocol.
func (m *PiManager) piGPIOLoop(inst *PiInstance) {
	var conn net.Conn
	for i := 0; i < 120; i++ {
		time.Sleep(200 * time.Millisecond)
		conn, _ = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", inst.gpioPort), time.Second)
		if conn != nil {
			break
		}
	}
	if conn == nil {
		return // GPIO shim not available — serial-only mode
	}

	inst.mu.Lock()
	inst.gpioConn = conn
	inst.mu.Unlock()

	// Read GPIO events: "GPIO <pin> <0|1>\n"
	buf := make([]byte, 256)
	var lineBuf []byte
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		for i := 0; i < n; i++ {
			if buf[i] == '\n' {
				line := string(lineBuf)
				lineBuf = lineBuf[:0]
				if strings.HasPrefix(line, "GPIO ") {
					parts := strings.Fields(line)
					if len(parts) == 3 {
						pin := 0
						state := 0
						fmt.Sscanf(parts[1], "%d", &pin)
						fmt.Sscanf(parts[2], "%d", &state)
						if inst.OnEvent != nil {
							inst.OnEvent(QemuEvent{
								Type: "gpio_change",
								Data: map[string]interface{}{"pin": pin, "state": state},
							})
						}
					}
				}
			} else {
				lineBuf = append(lineBuf, buf[i])
			}
		}
	}
}

// SendSerial writes bytes to the Pi's ttyAMA0.
func (m *PiManager) SendSerial(id string, data []byte) error {
	m.mu.Lock()
	inst, ok := m.instances[id]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("Pi instance %q not found", id)
	}
	inst.mu.Lock()
	conn := inst.serialConn
	inst.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("serial not connected")
	}
	_, err := conn.Write(data)
	return err
}

// SendGPIO drives a GPIO pin on the Pi via the shim protocol.
func (m *PiManager) SendGPIO(id string, pin, state int) error {
	m.mu.Lock()
	inst, ok := m.instances[id]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("Pi instance %q not found", id)
	}
	inst.mu.Lock()
	conn := inst.gpioConn
	inst.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("GPIO shim not connected")
	}
	_, err := fmt.Fprintf(conn, "SET %d %d\n", pin, state)
	return err
}

// StopInstance stops a Pi QEMU instance.
func (m *PiManager) StopInstance(id string) {
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
	if inst.gpioConn != nil {
		inst.gpioConn.Close()
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
	case <-time.After(5 * time.Second):
	}

	// Docker: force-stop named container
	if m.cfg.DockerImage != "" {
		exec.Command(m.cfg.DockerBinary, "stop", "-t", "1", "pi-"+id).Run()
		exec.Command(m.cfg.DockerBinary, "rm", "-f", "pi-"+id).Run()
	}

	m.removeInstance(id)
}

func (m *PiManager) removeInstance(id string) {
	m.mu.Lock()
	inst, ok := m.instances[id]
	delete(m.instances, id)
	m.mu.Unlock()
	if ok && inst.overlayPath != "" {
		os.Remove(inst.overlayPath)
	}
}

// StopAll stops all running Pi instances.
func (m *PiManager) StopAll() {
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

// sweepLoop periodically kills instances that exceed InstanceTimeout.
func (m *PiManager) sweepLoop() {
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

func (m *PiManager) sweep() {
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
func (m *PiManager) Shutdown() {
	close(m.done)
	m.StopAll()
}

// cleanupOrphanContainers kills leftover pi-* containers from a previous crash.
func (m *PiManager) cleanupOrphanContainers() {
	rt := m.cfg.DockerBinary
	out, err := exec.Command(rt, "ps", "-a", "--filter", "name=pi-", "--format", "{{.Names}}").Output()
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

// InstanceCount returns the number of running Pi instances.
func (m *PiManager) InstanceCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.instances)
}

// IsRunning checks if a Pi instance is running.
func (m *PiManager) IsRunning(id string) bool {
	m.mu.Lock()
	_, ok := m.instances[id]
	m.mu.Unlock()
	return ok
}
