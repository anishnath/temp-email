package arduino

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JobStore manages compile job artifacts on disk with automatic cleanup.
//
// Layout: {BaseDir}/{jobId}/sketch.ino.merged.bin, sketch.ino.bin, etc.
//
// Jobs auto-expire after JobTTL. A background goroutine sweeps every SweepInterval.
// Jobs can also be consumed (moved to QEMU), which extends their lifetime.
type JobStore struct {
	BaseDir       string        // e.g. /tmp/arduino-jobs
	JobTTL        time.Duration // how long jobs live (default 5 min)
	SweepInterval time.Duration // cleanup sweep interval (default 60s)

	mu   sync.Mutex
	jobs map[string]*jobEntry
	done chan struct{}
}

type jobEntry struct {
	id        string
	dir       string
	board     string
	createdAt time.Time
	consumed  bool // true after simulate/start reads the firmware
}

// DefaultJobStoreConfig returns a JobStore with env-configurable settings.
//
// Environment:
//
//	ARDUINO_JOB_DIR       — base directory (default /tmp/arduino-jobs)
//	ARDUINO_JOB_TTL_SEC   — job TTL in seconds (default 300 = 5 min)
//	ARDUINO_JOB_SWEEP_SEC — sweep interval in seconds (default 60)
func DefaultJobStoreConfig() *JobStore {
	baseDir := strings.TrimSpace(os.Getenv("ARDUINO_JOB_DIR"))
	if baseDir == "" {
		baseDir = filepath.Join(os.TempDir(), "arduino-jobs")
	}
	ttl := 5 * time.Minute
	if v := os.Getenv("ARDUINO_JOB_TTL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ttl = time.Duration(n) * time.Second
		}
	}
	sweep := 60 * time.Second
	if v := os.Getenv("ARDUINO_JOB_SWEEP_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sweep = time.Duration(n) * time.Second
		}
	}
	return &JobStore{
		BaseDir:       baseDir,
		JobTTL:        ttl,
		SweepInterval: sweep,
		jobs:          make(map[string]*jobEntry),
		done:          make(chan struct{}),
	}
}

// Start begins the background cleanup goroutine.
func (s *JobStore) Start() {
	_ = os.MkdirAll(s.BaseDir, 0o755)
	go s.sweepLoop()
}

// Stop terminates the cleanup goroutine.
func (s *JobStore) Stop() {
	close(s.done)
}

func generateJobID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// CreateJob creates a new job directory and returns the job ID + path.
func (s *JobStore) CreateJob(board string) (jobID string, jobDir string, err error) {
	jobID = generateJobID()
	jobDir = filepath.Join(s.BaseDir, jobID)
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		return "", "", fmt.Errorf("creating job dir: %w", err)
	}

	s.mu.Lock()
	s.jobs[jobID] = &jobEntry{
		id:        jobID,
		dir:       jobDir,
		board:     board,
		createdAt: time.Now(),
	}
	s.mu.Unlock()

	return jobID, jobDir, nil
}

// GetJobDir returns the directory for a job, or error if not found / expired.
func (s *JobStore) GetJobDir(jobID string) (string, error) {
	s.mu.Lock()
	entry, ok := s.jobs[jobID]
	s.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("job %q not found (expired or invalid)", jobID)
	}
	return entry.dir, nil
}

// GetMergedBinPath returns the path to sketch.ino.merged.bin for a job.
func (s *JobStore) GetMergedBinPath(jobID string) (string, error) {
	dir, err := s.GetJobDir(jobID)
	if err != nil {
		return "", err
	}
	// Look in build/ subdirectory (where arduino-cli outputs)
	merged := filepath.Join(dir, "build", "sketch.ino.merged.bin")
	if _, err := os.Stat(merged); err != nil {
		// Also try the direct job dir
		merged = filepath.Join(dir, "sketch.ino.merged.bin")
		if _, err := os.Stat(merged); err != nil {
			return "", fmt.Errorf("merged.bin not found for job %q", jobID)
		}
	}
	return merged, nil
}

// GetBinPath returns the path to sketch.ino.bin for a job.
func (s *JobStore) GetBinPath(jobID string) (string, error) {
	dir, err := s.GetJobDir(jobID)
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "build", "sketch.ino.bin")
	if _, err := os.Stat(bin); err != nil {
		return "", fmt.Errorf("bin not found for job %q", jobID)
	}
	return bin, nil
}

// MarkConsumed marks a job as consumed (firmware loaded into QEMU).
// Consumed jobs still expire after JobTTL from creation time.
func (s *JobStore) MarkConsumed(jobID string) {
	s.mu.Lock()
	if e, ok := s.jobs[jobID]; ok {
		e.consumed = true
	}
	s.mu.Unlock()
}

// RemoveJob deletes a job and its artifacts immediately.
func (s *JobStore) RemoveJob(jobID string) {
	s.mu.Lock()
	entry, ok := s.jobs[jobID]
	delete(s.jobs, jobID)
	s.mu.Unlock()
	if ok {
		os.RemoveAll(entry.dir)
	}
}

// JobCount returns the number of active jobs.
func (s *JobStore) JobCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.jobs)
}

// sweepLoop periodically removes expired jobs.
func (s *JobStore) sweepLoop() {
	ticker := time.NewTicker(s.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

func (s *JobStore) sweep() {
	now := time.Now()
	var expired []string

	s.mu.Lock()
	for id, entry := range s.jobs {
		if now.Sub(entry.createdAt) > s.JobTTL {
			expired = append(expired, id)
		}
	}
	for _, id := range expired {
		if e, ok := s.jobs[id]; ok {
			os.RemoveAll(e.dir)
			delete(s.jobs, id)
		}
	}
	s.mu.Unlock()
}
