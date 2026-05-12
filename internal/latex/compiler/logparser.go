package compiler

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ParsedLog contains extracted errors and warnings from pdflatex output.
type ParsedLog struct {
	Errors   []LogError
	Warnings []LogWarning
	RawLines []string
}

// LogError represents a single error.
type LogError struct {
	Line    int
	Message string
	Raw     string
}

// LogWarning represents a warning (e.g. Overfull \hbox).
type LogWarning struct {
	Line int
	Text string
	Raw  string
}

var (
	reUndefinedSeq  = regexp.MustCompile(`^! Undefined control sequence\.`)
	reMissingDollar = regexp.MustCompile(`^! Missing \$ inserted\.`)
	reFileNotFound  = regexp.MustCompile(`[Ff]ile .*?\x60([^\x60']+)'[^.]*not found`)
	reRunawayArg    = regexp.MustCompile(`^! Runaway argument`)
	reEmergencyStop = regexp.MustCompile(`^! Emergency stop`)
	reOverfullHbox  = regexp.MustCompile(`Overfull \\hbox`)
	reLineNum       = regexp.MustCompile(`l\.(\d+)`)
	reUndefinedCmd  = regexp.MustCompile(`l\.(\d+)\s+([^\s].*)`)
)

// ParseLog processes raw pdflatex log lines and extracts structured errors/warnings.
func ParseLog(lines []string) *ParsedLog {
	pl := &ParsedLog{RawLines: lines}
	pl.Errors = []LogError{}
	pl.Warnings = []LogWarning{}

	for i, line := range lines {
		if reUndefinedSeq.MatchString(line) {
			lineNum := extractLineNum(lines, i)
			cmd := extractCmd(lines, i)
			pl.Errors = append(pl.Errors, LogError{
				Line: lineNum, Message: "Unknown LaTeX command: " + cmd + " on line " + strconv.Itoa(lineNum), Raw: line,
			})
		} else if reMissingDollar.MatchString(line) {
			lineNum := extractLineNum(lines, i)
			pl.Errors = append(pl.Errors, LogError{Line: lineNum, Message: "Math mode error near line " + strconv.Itoa(lineNum), Raw: line})
		} else if reFileNotFound.MatchString(line) {
			lineNum := extractLineNum(lines, i)
			fn := extractFilename(lines, i)
			pl.Errors = append(pl.Errors, LogError{Line: lineNum, Message: "Image or file not found: " + fn, Raw: line})
		} else if reRunawayArg.MatchString(line) {
			lineNum := extractLineNum(lines, i)
			pl.Errors = append(pl.Errors, LogError{Line: lineNum, Message: "Missing closing brace near line " + strconv.Itoa(lineNum), Raw: line})
		} else if reEmergencyStop.MatchString(line) {
			lineNum := extractLineNum(lines, i)
			pl.Errors = append(pl.Errors, LogError{Line: lineNum, Message: "Fatal error — check syntax near line " + strconv.Itoa(lineNum), Raw: line})
		} else if strings.HasPrefix(line, "! LaTeX Error") {
			lineNum := extractLineNum(lines, i)
			msg := strings.TrimSpace(strings.TrimPrefix(line, "!"))
			pl.Errors = append(pl.Errors, LogError{Line: lineNum, Message: msg, Raw: line})
		} else if strings.HasPrefix(line, "! Package ") && strings.Contains(line, "Error:") {
			lineNum := extractLineNum(lines, i)
			msg := strings.TrimSpace(strings.TrimPrefix(line, "!"))
			pl.Errors = append(pl.Errors, LogError{Line: lineNum, Message: msg, Raw: line})
		} else if reOverfullHbox.MatchString(line) {
			lineNum := extractLineNum(lines, i)
			pl.Warnings = append(pl.Warnings, LogWarning{Line: lineNum, Text: "Overfull \\hbox", Raw: line})
		}
	}
	return pl
}

func extractLineNum(lines []string, errIdx int) int {
	for i := errIdx; i >= 0 && errIdx-i < 5; i-- {
		if m := reLineNum.FindStringSubmatch(lines[i]); len(m) > 1 {
			n, _ := strconv.Atoi(m[1])
			return n
		}
	}
	for i := errIdx; i < len(lines) && i-errIdx < 15; i++ {
		if m := reLineNum.FindStringSubmatch(lines[i]); len(m) > 1 {
			n, _ := strconv.Atoi(m[1])
			return n
		}
	}
	return 0
}

const maxLatexLogPeekBytes = 512 * 1024
const maxLatexSummaryLen = 4096

// SummarizeDocumentLog reads document.log in workDir and returns a short explanation
// (first structured error, else the last "! ..." block, else the log tail). Suitable for API and logs.
func SummarizeDocumentLog(workDir string) string {
	logPath := filepath.Join(workDir, "document.log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		return "could not read document.log: " + err.Error()
	}
	s := string(data)
	if len(s) > maxLatexLogPeekBytes {
		s = s[len(s)-maxLatexLogPeekBytes:]
	}
	lines := strings.Split(s, "\n")
	parsed := ParseLog(lines)
	if len(parsed.Errors) > 0 {
		return trimLatexSummary(parsed.Errors[0].Message)
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "!") {
			end := i + 15
			if end > len(lines) {
				end = len(lines)
			}
			return trimLatexSummary(strings.Join(lines[i:end], "\n"))
		}
	}
	if len(lines) > 30 {
		return trimLatexSummary(strings.Join(lines[len(lines)-30:], "\n"))
	}
	return trimLatexSummary(strings.TrimSpace(s))
}

func trimLatexSummary(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLatexSummaryLen {
		return s
	}
	return s[:maxLatexSummaryLen] + "…"
}

func extractCmd(lines []string, errIdx int) string {
	for i := errIdx; i >= 0 && errIdx-i < 5; i-- {
		if m := reUndefinedCmd.FindStringSubmatch(lines[i]); len(m) > 2 {
			return m[2]
		}
	}
	for i := errIdx; i < len(lines) && i-errIdx < 15; i++ {
		if m := reUndefinedCmd.FindStringSubmatch(lines[i]); len(m) > 2 {
			return m[2]
		}
	}
	return "?"
}

func extractFilename(lines []string, errIdx int) string {
	m := reFileNotFound.FindStringSubmatch(lines[errIdx])
	if len(m) > 1 && m[1] != "" {
		return m[1]
	}
	return "?"
}
