package compiler

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"latex-api/internal/model"
)

func TestCompile_Integration(t *testing.T) {
	if _, err := exec.LookPath("pdflatex"); err != nil {
		t.Skip("pdflatex not installed, skipping integration test")
	}

	// Use a temp dir to avoid polluting /tmp/latex-jobs
	dir, err := os.MkdirTemp("", "latex-compiler-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	os.Setenv("LATEX_TEMP_DIR", dir)
	defer os.Unsetenv("LATEX_TEMP_DIR")

	source := `\documentclass{article}\begin{document}Hello World\end{document}`
	job := model.NewCompileJob(source, nil)
	model.RegisterJob(job)
	defer model.DeleteJob(job.ID)

	Compile(job)
	<-job.Done

	if job.GetStatus() != model.StatusDone {
		t.Fatalf("expected done, got %s: %s", job.GetStatus(), job.Error)
	}
	if job.PDFPath == "" {
		t.Fatal("PDFPath not set")
	}
	if _, err := os.Stat(job.PDFPath); err != nil {
		t.Fatalf("PDF file missing: %v", err)
	}
	if filepath.Ext(job.PDFPath) != ".pdf" {
		t.Errorf("expected .pdf extension, got %s", job.PDFPath)
	}
}
