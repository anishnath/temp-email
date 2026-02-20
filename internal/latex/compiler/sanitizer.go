package compiler

import (
	"regexp"
	"strings"
)

// SanitizeError describes why source was rejected.
type SanitizeError struct {
	Reason string
	Match  string
}

func (e *SanitizeError) Error() string {
	return e.Reason + ": " + e.Match
}

// Blocked patterns (case-insensitive where sensible).
var blockedPatterns = []struct {
	re     *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`(?i)\\write18`), "write18 not allowed"},
	{regexp.MustCompile(`(?i)\\input\s*\{\s*/`), "absolute path in \\input not allowed"},
	{regexp.MustCompile(`(?i)\\openin`), "\\openin not allowed"},
	{regexp.MustCompile(`(?i)\\catcode`), "\\catcode not allowed"},
	{regexp.MustCompile(`(?i)\\immediate`), "\\immediate not allowed"},
	{regexp.MustCompile(`(?i)\\openout`), "\\openout not allowed"},
	{regexp.MustCompile(`(?i)enableWrite18`), "enableWrite18 not allowed"},
	{regexp.MustCompile(`(?i)shell-escape`), "shell-escape not allowed"},
}

// Check validates LaTeX source and returns an error if dangerous commands are found.
func Check(source string) error {
	s := source
	for _, p := range blockedPatterns {
		if loc := p.re.FindStringIndex(s); loc != nil {
			match := s[loc[0]:loc[1]]
			return &SanitizeError{Reason: p.reason, Match: match}
		}
	}
	if strings.Contains(strings.ToLower(s), "\\input{/") {
		return &SanitizeError{Reason: "absolute path in \\input not allowed", Match: "\\input{/"}
	}
	return nil
}
