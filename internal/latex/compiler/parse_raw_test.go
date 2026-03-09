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
