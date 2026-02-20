package compiler

import (
	"regexp"
	"strconv"
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
	return 0
}

func extractCmd(lines []string, errIdx int) string {
	for i := errIdx; i >= 0 && errIdx-i < 5; i-- {
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
