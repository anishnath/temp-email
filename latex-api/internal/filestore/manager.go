package filestore

import (
	"os"
	"path/filepath"
	"time"

	"latex-api/config"
)

// CreateJobDir creates /tmp/latex-jobs/{jobId}/ and returns the path.
func CreateJobDir(jobID string) (string, error) {
	base := "/tmp/latex-jobs"
	if cfg := config.Load(); cfg != nil {
		base = cfg.LatexTempDir
	}
	dir := filepath.Join(base, jobID)
	return dir, os.MkdirAll(dir, 0750)
}

// Cleanup removes the job directory entirely.
func Cleanup(jobID string) {
	base := "/tmp/latex-jobs"
	if cfg := config.Load(); cfg != nil {
		base = cfg.LatexTempDir
	}
	dir := filepath.Join(base, jobID)
	_ = os.RemoveAll(dir)
}

// ScheduleCleanup runs Cleanup after the given duration.
func ScheduleCleanup(jobID string, after time.Duration) {
	time.AfterFunc(after, func() { Cleanup(jobID) })
}
