package compiler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNeedsBibTeX(t *testing.T) {
	dir := t.TempDir()

	if needsBibTeX(dir) {
		t.Fatal("expected false with no aux")
	}

	aux := filepath.Join(dir, documentBase+".aux")
	if err := os.WriteFile(aux, []byte(`\bibstyle{IEEEtran}`), 0600); err != nil {
		t.Fatal(err)
	}
	if !needsBibTeX(dir) {
		t.Fatal("expected true with \\bibstyle")
	}
}
