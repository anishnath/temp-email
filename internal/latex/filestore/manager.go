package filestore

import (
	"os"
	"path/filepath"
	"time"
)

func latexTempDir() string {
	if d := os.Getenv("LATEX_TEMP_DIR"); d != "" {
		return d
	}
	return "/tmp/latex-jobs"
}

// CreateJobDir creates {LATEX_TEMP_DIR}/{jobId}/ and returns the path.
func CreateJobDir(jobID string) (string, error) {
	dir := filepath.Join(latexTempDir(), jobID)
	return dir, os.MkdirAll(dir, 0750)
}

// Cleanup removes the job directory entirely.
func Cleanup(jobID string) {
	dir := filepath.Join(latexTempDir(), jobID)
	_ = os.RemoveAll(dir)
}

// ScheduleCleanup runs Cleanup after the given duration.
func ScheduleCleanup(jobID string, after time.Duration) {
	time.AfterFunc(after, func() { Cleanup(jobID) })
}

// CleanupUpload removes an upload directory (uploads/{fileId}/).
func CleanupUpload(fileID string) {
	dir := filepath.Join(latexTempDir(), "uploads", fileID)
	_ = os.RemoveAll(dir)
}

// ScheduleUploadCleanup runs CleanupUpload after the given duration.
func ScheduleUploadCleanup(fileID string, after time.Duration) {
	time.AfterFunc(after, func() { CleanupUpload(fileID) })
}

// CopyUploadToJobDir copies all files from uploads/{fileID}/ into the job work dir.
// Returns error if upload dir does not exist or is empty.
func CopyUploadToJobDir(fileID, jobDir string) error {
	uploadDir := filepath.Join(latexTempDir(), "uploads", fileID)
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(uploadDir, e.Name())
		dst := filepath.Join(jobDir, e.Name())
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return err
		}
	}
	return nil
}
