package compiler

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

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

func TestCompile_IntegrationWithBibTeX(t *testing.T) {
	if _, err := exec.LookPath("pdflatex"); err != nil {
		t.Skip("pdflatex not installed, skipping integration test")
	}
	if _, err := exec.LookPath("bibtex"); err != nil {
		t.Skip("bibtex not installed, skipping integration test")
	}

	dir, err := os.MkdirTemp("", "latex-compiler-bib-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	os.Setenv("LATEX_TEMP_DIR", dir)
	defer os.Unsetenv("LATEX_TEMP_DIR")

	source := `\documentclass{article}
\begin{document}
Cite~\cite{knuth}.
\bibliographystyle{plain}
\bibliography{refs}
\end{document}`

	bib := `@book{knuth,
  author = {Donald E. Knuth},
  title = {The TeXbook},
  year = {1984},
  publisher = {Addison-Wesley}
}`

	fileID := uuid.New().String()
	uploadDir := filepath.Join(dir, "uploads", fileID)
	if err := os.MkdirAll(uploadDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploadDir, "refs.bib"), []byte(bib), 0600); err != nil {
		t.Fatal(err)
	}

	job := model.NewCompileJob(source, []string{fileID})
	model.RegisterJob(job)
	defer model.DeleteJob(job.ID)

	Compile(job)
	<-job.Done

	if job.GetStatus() != model.StatusDone {
		t.Fatalf("expected done, got %s: %s", job.GetStatus(), job.Error)
	}
	if _, err := os.Stat(filepath.Join(job.WorkDir, documentBase+".bbl")); err != nil {
		t.Fatalf("expected .bbl after bibtex: %v", err)
	}
}

func TestCompileWorkDir_WithBibTeX(t *testing.T) {
	if _, err := exec.LookPath("pdflatex"); err != nil {
		t.Skip("pdflatex not installed")
	}
	if _, err := exec.LookPath("bibtex"); err != nil {
		t.Skip("bibtex not installed")
	}

	workDir := t.TempDir()
	source := `\documentclass{article}
\begin{document}
See~\cite{knuth}.
\bibliographystyle{plain}
\bibliography{refs}
\end{document}`
	if err := os.WriteFile(filepath.Join(workDir, documentName), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "refs.bib"), []byte(`@book{knuth,
  author = {Donald E. Knuth},
  title = {The TeXbook},
  year = {1984},
  publisher = {Addison-Wesley}
}`), 0600); err != nil {
		t.Fatal(err)
	}

	job := model.NewCompileJob(source, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := runCompilePipeline(ctx, job, workDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(workDir, documentBase+".bbl")); err != nil {
		t.Fatalf("missing bbl: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir, documentBase+".pdf")); err != nil {
		t.Fatalf("missing pdf: %v", err)
	}
}
