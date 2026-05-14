package compiler

import (
	"strings"
	"testing"
)

func TestParseRaw(t *testing.T) {
	raw := `\usetikzlibrary {angles,calc,quotes}
\begin{tikzpicture}[angle radius=.75cm]
  \node (A) at (-2,0) {$A$};
\end{tikzpicture}`
	p, err := ParseRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.TikzBlock, `\begin{tikzpicture}[angle radius=.75cm]`) {
		t.Errorf("TikzBlock should contain angle radius option, got: %s", p.TikzBlock[:min(100, len(p.TikzBlock))])
	}
	if !strings.Contains(p.TikzBlock, `\node (A) at (-2,0) {$A$}`) {
		t.Errorf("TikzBlock should contain node, got: %s", p.TikzBlock)
	}
	if !strings.Contains(p.TikzBlock, `\end{tikzpicture}`) {
		t.Errorf("TikzBlock should contain \\end{tikzpicture}")
	}
	wantLibs := map[string]bool{"angles": true, "calc": true, "quotes": true}
	for _, lib := range p.TikzLibraries {
		if !wantLibs[lib] {
			t.Errorf("unexpected library: %s", lib)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestParseRawStripsDocumentClassAndBeginDocument is a regression for the
// "completely different output" bug filed on 2026-05-15. Pasting a full
// \documentclass{standalone}...\end{document} TikZ document used to leak
// \documentclass and \begin{document} into the wrapper body via the
// "carry preamble before \begin{tikzpicture}" branch, triggering
// "LaTeX Error: Can be used only in preamble." (latex still emitted a DVI
// under -interaction=nonstopmode, producing a visibly broken SVG).
func TestParseRawStripsDocumentClassAndBeginDocument(t *testing.T) {
	raw := `\documentclass{standalone}

\usepackage{pgfplots}
\pgfplotsset{compat=1.8}

\begin{document}
\begin{tikzpicture}
  \node at (0,0) {hi};
\end{tikzpicture}
\end{document}`
	p, err := ParseRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Body must not carry the document-class line through.
	if strings.Contains(p.TikzBlock, `\documentclass`) {
		t.Errorf("\\documentclass leaked into TikzBlock: %s", p.TikzBlock)
	}
	if strings.Contains(p.TikzBlock, `\begin{document}`) {
		t.Errorf("\\begin{document} leaked into TikzBlock: %s", p.TikzBlock)
	}
	if strings.Contains(p.TikzBlock, `\end{document}`) {
		t.Errorf("\\end{document} leaked into TikzBlock: %s", p.TikzBlock)
	}
	// pgfplotsset SHOULD be preserved (it's a valid in-body config call).
	if !strings.Contains(p.TikzBlock, `\pgfplotsset{compat=1.8}`) {
		t.Errorf("\\pgfplotsset config should be preserved in TikzBlock: %s", p.TikzBlock)
	}
	// pgfplots package extracted into Packages, not into TikzLibraries.
	hasPgfplotsPackage := false
	for _, p := range p.Packages {
		if p == "pgfplots" {
			hasPgfplotsPackage = true
		}
	}
	if !hasPgfplotsPackage {
		t.Errorf("expected pgfplots in Packages, got: %v", p.Packages)
	}
	for _, lib := range p.TikzLibraries {
		if lib == "pgfplots" {
			t.Errorf("pgfplots wrongly listed as a TikZ library: %v", p.TikzLibraries)
		}
	}
}
