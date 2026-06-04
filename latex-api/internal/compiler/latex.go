package compiler

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"latex-api/config"
	"latex-api/internal/filestore"
	"latex-api/internal/model"
)

const documentName = "document.tex"

// Compile runs pdflatex (and bibtex when needed) on the job's source and streams logs.
func Compile(job *model.CompileJob) {
	defer close(job.Done)

	closeLogs := false
	defer func() {
		if closeLogs {
			close(job.LogLines)
		}
	}()

	workDir, err := filestore.CreateJobDir(job.ID)
	if err != nil {
		closeLogs = true
		job.SetError("failed to create work directory: " + err.Error())
		return
	}
	job.WorkDir = workDir

	cleanupAfter := 1 * time.Hour
	if cfg := config.Load(); cfg != nil {
		cleanupAfter = cfg.CleanupAfter
	}
	defer func() {
		filestore.ScheduleCleanup(job.ID, cleanupAfter)
	}()

	if len(job.FileIDs) > 0 {
		if err := filestore.CopyUploadedFiles(job.FileIDs, workDir); err != nil {
			closeLogs = true
			job.SetError("failed to copy uploaded files: " + err.Error())
			return
		}
	}

	texPath := filepath.Join(workDir, documentName)
	if err := os.WriteFile(texPath, []byte(job.Source), 0600); err != nil {
		closeLogs = true
		job.SetError("failed to write source: " + err.Error())
		return
	}

	timeout := 30 * time.Second
	if cfg := config.Load(); cfg != nil {
		timeout = cfg.LatexTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	closeLogs = true

	if err := runCompilePipeline(ctx, job, workDir); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			job.SetError(fmt.Sprintf(
				"Compilation timed out after %s — document is too complex or stuck in a loop. "+
					"Increase LATEX_TIMEOUT_SECONDS to allow longer runs.", timeout))
			return
		}
		job.SetError(err.Error())
		return
	}

	pdfPath := filepath.Join(workDir, documentBase+".pdf")
	if _, err := os.Stat(pdfPath); err != nil {
		job.SetError("PDF was not produced: " + err.Error())
		return
	}

	job.SetDone(pdfPath)
}

func runCompilePipeline(ctx context.Context, job *model.CompileJob, workDir string) error {
	if err := runPDFLaTeX(ctx, job, workDir); err != nil {
		return err
	}

	if needsBibTeX(workDir) {
		select {
		case job.LogLines <- "=== Running BibTeX ===":
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := runBibTeX(ctx, job, workDir); err != nil {
			return err
		}
		for i := 0; i < 2; i++ {
			if err := runPDFLaTeX(ctx, job, workDir); err != nil {
				return err
			}
		}
	}

	return nil
}

func runPDFLaTeX(ctx context.Context, job *model.CompileJob, workDir string) error {
	select {
	case job.LogLines <- "=== Running pdfLaTeX ===":
	case <-ctx.Done():
		return ctx.Err()
	}
	return runCommand(ctx, job, workDir, "pdflatex",
		"-no-shell-escape",
		"-interaction=nonstopmode",
		documentName,
	)
}

func runBibTeX(ctx context.Context, job *model.CompileJob, workDir string) error {
	err := runCommand(ctx, job, workDir, "bibtex", documentBase)
	if err != nil {
		return fmt.Errorf("BibTeX failed — check .bib file names match \\bibliography{} and citations: %w", err)
	}
	return nil
}

func runCommand(ctx context.Context, job *model.CompileJob, workDir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = workDir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %w", name, err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			select {
			case job.LogLines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		se := bufio.NewScanner(stderr)
		for se.Scan() {
			select {
			case job.LogLines <- se.Text():
			case <-ctx.Done():
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	wg.Wait()

	if waitErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return ctx.Err()
		}
		if name == "pdflatex" {
			return fmt.Errorf("%s", parseCompileError(job, workDir))
		}
		return waitErr
	}
	return nil
}

func parseCompileError(job *model.CompileJob, workDir string) string {
	logPath := filepath.Join(workDir, documentBase+".log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		return "Compilation failed — could not read log"
	}
	lines := strings.Split(string(data), "\n")
	parsed := ParseLog(lines)
	if len(parsed.Errors) > 0 {
		return parsed.Errors[0].Message
	}
	return "Compilation failed — check LaTeX syntax"
}
