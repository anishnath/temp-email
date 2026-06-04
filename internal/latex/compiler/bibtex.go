package compiler

import (
	"os"
	"path/filepath"
	"strings"
)

const documentBase = "document"

// needsBibTeX reports whether the last pdflatex run wrote bibliography data to .aux.
func needsBibTeX(workDir string) bool {
	data, err := os.ReadFile(filepath.Join(workDir, documentBase+".aux"))
	if err != nil {
		return false
	}
	s := string(data)
	return strings.Contains(s, "\\bibdata{") || strings.Contains(s, "\\bibstyle{")
}
