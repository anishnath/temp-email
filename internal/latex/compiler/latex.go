package compiler

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"temp-email/internal/latex/filestore"
	"temp-email/internal/latex/job"
)

const documentName = "document.tex"

// Compile runs pdflatex (and bibtex when needed) on the job's source and streams logs.
func Compile(j *job.CompileJob) {
	defer close(j.Done)

	closeLogs := false
	defer func() {
		if closeLogs {
			close(j.LogLines)
		}
	}()

	workDir, err := filestore.CreateJobDir(j.ID)
	if err != nil {
		closeLogs = true
		j.SetError("failed to create work directory: " + err.Error())
		return
	}
	j.WorkDir = workDir

	cleanupMin := 60
	if v := os.Getenv("LATEX_CLEANUP_AFTER_MINUTES"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			cleanupMin = n
		}
	}
	defer func() {
		filestore.ScheduleCleanup(j.ID, time.Duration(cleanupMin)*time.Minute)
	}()

	for _, fileID := range j.FileIDs {
		if err := filestore.CopyUploadToJobDir(fileID, workDir); err != nil {
			closeLogs = true
			j.SetError("failed to copy upload " + fileID + ": " + err.Error())
			return
		}
	}

	texPath := filepath.Join(workDir, documentName)
	if err := os.WriteFile(texPath, []byte(j.Source), 0600); err != nil {
		closeLogs = true
		j.SetError("failed to write source: " + err.Error())
		return
	}

	timeoutSec := 90
	if v := os.Getenv("LATEX_TIMEOUT_SECONDS"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			timeoutSec = n
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	closeLogs = true

	if err := runCompilePipeline(ctx, j, workDir); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			j.SetError(fmt.Sprintf(
				"Compilation timed out after %ds — document is too complex or stuck in a loop. "+
					"Increase LATEX_TIMEOUT_SECONDS to allow longer runs.", timeoutSec))
			return
		}
		j.SetError(err.Error())
		return
	}

	pdfPath := filepath.Join(workDir, documentBase+".pdf")
	if _, err := os.Stat(pdfPath); err != nil {
		j.SetError("PDF was not produced: " + err.Error())
		return
	}

	warning := strings.TrimSpace(SummarizeDocumentLog(workDir))
	if warning != "" && !strings.HasPrefix(warning, "could not read document.log") {
		j.SetDoneWithWarning(pdfPath, warning)
		return
	}
	j.SetDone(pdfPath)
}

func runCompilePipeline(ctx context.Context, j *job.CompileJob, workDir string) error {
	if err := runPDFLaTeX(ctx, j, workDir); err != nil {
		return err
	}

	if needsBibTeX(workDir) {
		select {
		case j.LogLines <- "=== Running BibTeX ===":
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := runBibTeX(ctx, j, workDir); err != nil {
			return err
		}
		for i := 0; i < 2; i++ {
			if err := runPDFLaTeX(ctx, j, workDir); err != nil {
				return err
			}
		}
	}

	return nil
}

func runPDFLaTeX(ctx context.Context, j *job.CompileJob, workDir string) error {
	select {
	case j.LogLines <- "=== Running pdfLaTeX ===":
	case <-ctx.Done():
		return ctx.Err()
	}
	return runCommand(ctx, j, workDir, "pdflatex",
		"-no-shell-escape",
		"-interaction=nonstopmode",
		documentName,
	)
}

func runBibTeX(ctx context.Context, j *job.CompileJob, workDir string) error {
	err := runCommand(ctx, j, workDir, "bibtex", documentBase)
	if err != nil {
		return fmt.Errorf("BibTeX failed — check .bib file names match \\bibliography{} and citation keys: %w", err)
	}
	return nil
}

func runCommand(ctx context.Context, j *job.CompileJob, workDir, name string, args ...string) error {
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
			case j.LogLines <- scanner.Text():
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
			case j.LogLines <- se.Text():
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
			pdfPath := filepath.Join(workDir, documentBase+".pdf")
			if _, statErr := os.Stat(pdfPath); statErr == nil {
				return nil
			}
			summary := SummarizeDocumentLog(workDir)
			if summary != "" {
				return fmt.Errorf("%s", summary)
			}
			return fmt.Errorf("pdfLaTeX failed")
		}
		return waitErr
	}
	return nil
}
