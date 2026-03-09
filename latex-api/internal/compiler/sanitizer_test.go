package compiler

import (
	"errors"
	"testing"
)

func TestCheck_SafeSource(t *testing.T) {
	safe := `\documentclass{article}\begin{document}Hello \textbf{world}\end{document}`
	if err := Check(safe); err != nil {
		t.Errorf("expected safe source to pass: %v", err)
	}
}

func TestCheck_BlockedPatterns(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{"write18", `\documentclass{article}\begin{document}\write18{ls}\end{document}`},
		{"input absolute", `\documentclass{article}\begin{document}\input{/etc/passwd}\end{document}`},
		{"openin", `\documentclass{article}\begin{document}\openin\foo\end{document}`},
		{"catcode", `\documentclass{article}\begin{document}\catcode\end{document}`},
		{"immediate", `\documentclass{article}\begin{document}\immediate\write\end{document}`},
		{"openout", `\documentclass{article}\begin{document}\openout\foo\end{document}`},
		{"enableWrite18", `\documentclass{article}\begin{document}enableWrite18\end{document}`},
		{"shell-escape", `\documentclass{article}\begin{document}shell-escape\end{document}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(tt.source)
			if err == nil {
				t.Error("expected sanitizer to reject")
			}
			var sErr *SanitizeError
			if !errors.As(err, &sErr) {
				t.Errorf("expected SanitizeError, got %T", err)
			}
		})
	}
}
