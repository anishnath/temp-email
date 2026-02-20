package compiler

import (
	"bufio"
	"context"
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

// Compile runs pdflatex on the job's source and streams logs to job.LogLines.
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

	// Copy uploaded files into job dir so LaTeX can reference them
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

	timeoutSec := 30
	if v := os.Getenv("LATEX_TIMEOUT_SECONDS"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			timeoutSec = n
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
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
		j.SetError("failed to create stdout pipe: " + err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		closeLogs = true
		j.SetError("failed to create stderr pipe: " + err.Error())
		return
	}

	if err := cmd.Start(); err != nil {
		closeLogs = true
		j.SetError("failed to start pdflatex: " + err.Error())
		return
	}
	closeLogs = true

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

	if err := cmd.Wait(); err != nil {
		wg.Wait()
		pdfPath := filepath.Join(workDir, strings.TrimSuffix(documentName, ".tex")+".pdf")
		if _, statErr := os.Stat(pdfPath); statErr == nil {
			// PDF was produced despite errors (e.g. missing image, draft mode)
			j.SetDoneWithWarning(pdfPath, parseCompileError(j, workDir))
			return
		}
		j.SetError(parseCompileError(j, workDir))
		return
	}
	wg.Wait()

	pdfPath := filepath.Join(workDir, strings.TrimSuffix(documentName, ".tex")+".pdf")
	if _, err := os.Stat(pdfPath); err != nil {
		j.SetError("PDF was not produced: " + err.Error())
		return
	}
	j.SetDone(pdfPath)
}

func parseCompileError(j *job.CompileJob, workDir string) string {
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
