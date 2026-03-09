package compiler

import (
	"bufio"
	"context"
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

// Compile runs pdflatex on the job's source and streams logs to job.LogLines.
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

	cmd := exec.CommandContext(ctx, "pdflatex",
		"-no-shell-escape",
		"-interaction=nonstopmode",
		documentName,
	)
	cmd.Dir = workDir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		closeLogs = true
		job.SetError("failed to create stdout pipe: " + err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		closeLogs = true
		job.SetError("failed to create stderr pipe: " + err.Error())
		return
	}

	if err := cmd.Start(); err != nil {
		closeLogs = true
		job.SetError("failed to start pdflatex: " + err.Error())
		return
	}
	closeLogs = true // from here on we write to LogLines, so we must close it

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

	if err := cmd.Wait(); err != nil {
		wg.Wait()
		job.SetError(parseCompileError(job, workDir))
		return
	}

	wg.Wait()

	pdfPath := filepath.Join(workDir, strings.TrimSuffix(documentName, ".tex")+".pdf")
	if _, err := os.Stat(pdfPath); err != nil {
		job.SetError("PDF was not produced: " + err.Error())
		return
	}
	// closeLogs already true, defer will close job.LogLines

	job.SetDone(pdfPath)
}

func parseCompileError(job *model.CompileJob, workDir string) string {
	logPath := filepath.Join(workDir, strings.TrimSuffix(documentName, ".tex")+".log")
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
