package filestore

import (
	"fmt"
	"io"
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

// CopyUploadedFiles copies all files for the given fileIDs into destDir.
// Each upload lives at {LatexTempDir}/uploads/{fileId}/{filename}.
func CopyUploadedFiles(fileIDs []string, destDir string) error {
	base := "/tmp/latex-jobs"
	if cfg := config.Load(); cfg != nil {
		base = cfg.LatexTempDir
	}
	uploadsBase := filepath.Join(base, "uploads")

	for _, fileID := range fileIDs {
		uploadDir := filepath.Join(uploadsBase, fileID)
		entries, err := os.ReadDir(uploadDir)
		if err != nil {
			return fmt.Errorf("fileId %q not found: %w", fileID, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			src := filepath.Join(uploadDir, entry.Name())
			dst := filepath.Join(destDir, entry.Name())
			if err := copyFile(src, dst); err != nil {
				return fmt.Errorf("failed to copy %q: %w", entry.Name(), err)
			}
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
