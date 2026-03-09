package compiler

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"temp-email/internal/latex/filestore"
	"temp-email/internal/latex/job"
)

// TikZ document template using dvisvgm class for clean SVG output.
// {{PACKAGES}} is replaced with user \usepackage{} and \usetikzlibrary{} lines.
// {{TIKZ_BLOCK}} is either the full \begin{tikzpicture}...\end{tikzpicture} (from raw) or \begin{tikzpicture}\n{{TIKZ}}\n\end{tikzpicture}.
const tikzTemplate = `\documentclass[dvisvgm]{minimal}
\usepackage{tikz}
\usetikzlibrary{arrows,arrows.meta,positioning,calc,shapes.geometric,trees}
{{PACKAGES}}

\begin{document}
{{TIKZ_BLOCK}}
\end{document}
`

var (
	reUsetikzlibrary   = regexp.MustCompile(`\\usetikzlibrary\s*\{([^}]+)\}`)
	reUsegdlibrary     = regexp.MustCompile(`\\usegdlibrary\s*\{([^}]+)\}`)
	reUsepackage       = regexp.MustCompile(`\\usepackage\s*(?:\[[^\]]*\])?\s*\{([^}]+)\}`)
	reTikzpictureBlock = regexp.MustCompile(`(?s)(\\begin\s*\{\s*tikzpicture\s*\}(?:\s*\[[^\]]*\])?\s*[\s\S]*?\\end\s*\{\s*tikzpicture\s*\})`)
)

// ParsedRaw holds the result of parsing a raw TikZ documentation block.
type ParsedRaw struct {
	TikzBlock     string // full \begin{tikzpicture}[opts]...\end{tikzpicture} or \tikz [...]
	Packages      []string
	TikzLibraries []string
	GDLibraries   []string // \usegdlibrary{...} for graph drawing
}

// reStripPreamble removes \usetikzlibrary, \usegdlibrary, \usepackage lines to avoid duplication.
var reStripPreamble = regexp.MustCompile(`(?m)^\s*\\usetikzlibrary\s*\{[^}]*\}\s*$|^\s*\\usegdlibrary\s*\{[^}]*\}\s*$|^\s*\\usepackage\s*(?:\[[^\]]*\])?\s*\{[^}]*\}\s*$`)

// ParseRaw extracts \usetikzlibrary, \usepackage, and the TikZ body from pasted documentation.
// Body is either \begin{tikzpicture}...\end{tikzpicture} or \tikz \datavisualization (etc.).
func ParseRaw(raw string) (*ParsedRaw, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("raw input is empty")
	}

	var packages, libs []string

	for _, m := range reUsetikzlibrary.FindAllStringSubmatch(raw, -1) {
		for _, name := range strings.Split(m[1], ",") {
			name = strings.TrimSpace(name)
			if name != "" && validPkgName.MatchString(name) {
				libs = append(libs, name)
			}
		}
	}
	for _, m := range reUsepackage.FindAllStringSubmatch(raw, -1) {
		for _, name := range strings.Split(m[1], ",") {
			name = strings.TrimSpace(name)
			if name != "" && validPkgName.MatchString(name) {
				packages = append(packages, name)
			}
		}
	}
	var gdLibs []string
	for _, m := range reUsegdlibrary.FindAllStringSubmatch(raw, -1) {
		for _, name := range strings.Split(m[1], ",") {
			name = strings.TrimSpace(name)
			if name != "" && validPkgName.MatchString(name) {
				gdLibs = append(gdLibs, name)
			}
		}
	}

	tikzMatch := reTikzpictureBlock.FindStringSubmatch(raw)
	if len(tikzMatch) >= 2 {
		tikzBlock := strings.TrimSpace(tikzMatch[1])
		return &ParsedRaw{TikzBlock: tikzBlock, Packages: packages, TikzLibraries: libs, GDLibraries: gdLibs}, nil
	}

	// Fallback: \tikz \graph, \tikz \datavisualization, or other \tikz content
	if strings.Contains(raw, "\\tikz") {
		body := reStripPreamble.ReplaceAllString(raw, "")
		body = strings.TrimSpace(body)
		if body != "" {
			return &ParsedRaw{TikzBlock: body, Packages: packages, TikzLibraries: libs, GDLibraries: gdLibs}, nil
		}
	}

	return nil, fmt.Errorf("no \\begin{tikzpicture}...\\end{tikzpicture} or \\tikz block found")
}

// validPkgName allows safe LaTeX package/library names: letters, digits, dots, hyphens.
var validPkgName = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// ValidatePackageNames checks package and library names; returns error if any are invalid.
func ValidatePackageNames(packages, tikzLibraries []string) error {
	for _, pkg := range packages {
		pkg = strings.TrimSpace(pkg)
		if pkg != "" && !validPkgName.MatchString(pkg) {
			return fmt.Errorf("invalid package name: %q", pkg)
		}
	}
	for _, lib := range tikzLibraries {
		lib = strings.TrimSpace(lib)
		if lib != "" && !validPkgName.MatchString(lib) {
			return fmt.Errorf("invalid tikz library name: %q", lib)
		}
	}
	return nil
}

// ValidateGDLibraryNames checks \usegdlibrary names.
func ValidateGDLibraryNames(gdLibraries []string) error {
	for _, lib := range gdLibraries {
		lib = strings.TrimSpace(lib)
		if lib != "" && !validPkgName.MatchString(lib) {
			return fmt.Errorf("invalid gd library name: %q", lib)
		}
	}
	return nil
}

func buildUserPreamble(packages, tikzLibraries, gdLibraries []string) (string, error) {
	var b strings.Builder
	for _, pkg := range packages {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		if !validPkgName.MatchString(pkg) {
			return "", fmt.Errorf("invalid package name: %q", pkg)
		}
		b.WriteString("\\usepackage{" + pkg + "}\n")
	}
	if len(tikzLibraries) > 0 {
		var libs []string
		for _, lib := range tikzLibraries {
			lib = strings.TrimSpace(lib)
			if lib == "" {
				continue
			}
			if !validPkgName.MatchString(lib) {
				return "", fmt.Errorf("invalid tikz library name: %q", lib)
			}
			libs = append(libs, lib)
		}
		if len(libs) > 0 {
			b.WriteString("\\usetikzlibrary{" + strings.Join(libs, ",") + "}\n")
		}
	}
	for _, lib := range gdLibraries {
		lib = strings.TrimSpace(lib)
		if lib == "" {
			continue
		}
		if !validPkgName.MatchString(lib) {
			return "", fmt.Errorf("invalid gd library name: %q", lib)
		}
		b.WriteString("\\usegdlibrary{" + lib + "}\n")
	}
	return b.String(), nil
}

// CompileTikZ runs latex + dvisvgm to produce SVG from TikZ code.
func CompileTikZ(j *job.CompileJob) {
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
		if n, err := parseInt(v); n > 0 && err == nil {
			cleanupMin = n
		}
	}
	defer func() {
		filestore.ScheduleCleanup(j.ID, time.Duration(cleanupMin)*time.Minute)
	}()

	// Copy uploaded files if any
	for _, fileID := range j.FileIDs {
		if err := filestore.CopyUploadToJobDir(fileID, workDir); err != nil {
			closeLogs = true
			j.SetError("failed to copy upload " + fileID + ": " + err.Error())
			return
		}
	}

	// Build preamble from user packages, TikZ libraries, and graph-drawing libraries
	preamble, err := buildUserPreamble(j.Packages, j.TikzLibraries, j.GDLibraries)
	if err != nil {
		closeLogs = true
		j.SetError(err.Error())
		return
	}

	// Build tikz block: full block from raw paste, or wrapped inner content
	var tikzBlock string
	if j.TikzBlock != "" {
		tikzBlock = j.TikzBlock
	} else {
		tikzBlock = "\\begin{tikzpicture}\n" + j.Tikz + "\n\\end{tikzpicture}"
	}

	// Write .tex file
	source := strings.ReplaceAll(tikzTemplate, "{{PACKAGES}}", preamble)
	source = strings.ReplaceAll(source, "{{TIKZ_BLOCK}}", tikzBlock)
	texPath := filepath.Join(workDir, "document.tex")
	if err := os.WriteFile(texPath, []byte(source), 0600); err != nil {
		closeLogs = true
		j.SetError("failed to write source: " + err.Error())
		return
	}

	timeoutSec := 30
	if v := os.Getenv("LATEX_TIMEOUT_SECONDS"); v != "" {
		if n, err := parseInt(v); n > 0 && err == nil {
			timeoutSec = n
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	closeLogs = true

	// Run latex
	latexCmd := exec.CommandContext(ctx, "latex", "-interaction=nonstopmode", "document.tex")
	latexCmd.Dir = workDir
	setDvisvgmEnv(latexCmd)

	stdout, err := latexCmd.StdoutPipe()
	if err != nil {
		j.SetError("failed to create stdout pipe: " + err.Error())
		return
	}
	stderr, err := latexCmd.StderrPipe()
	if err != nil {
		j.SetError("failed to create stderr pipe: " + err.Error())
		return
	}

	if err := latexCmd.Start(); err != nil {
		j.SetError("failed to start latex: " + err.Error())
		return
	}

	streamOutput(stdout, stderr, j.LogLines, ctx)

	latexErr := latexCmd.Wait()
	dviPath := filepath.Join(workDir, "document.dvi")
	if _, err := os.Stat(dviPath); err != nil {
		if latexErr != nil {
			j.SetError("latex failed: " + latexErr.Error())
		} else {
			j.SetError("DVI was not produced")
		}
		return
	}

	// Run dvisvgm (even if latex exited non-zero, DVI may be usable)
	svgPath := filepath.Join(workDir, "document.svg")
	dvisvgmCmd := exec.CommandContext(ctx, "dvisvgm", "--no-fonts", "-o", "document.svg", "document.dvi")
	dvisvgmCmd.Dir = workDir
	setDvisvgmEnv(dvisvgmCmd)

	dvisvgmOut, err := dvisvgmCmd.CombinedOutput()
	if err != nil {
		j.SetError("dvisvgm failed: " + string(dvisvgmOut))
		return
	}

	if _, err := os.Stat(svgPath); err != nil {
		j.SetError("SVG was not produced")
		return
	}

	if latexErr != nil {
		j.SetDoneSVGWithWarning(svgPath, "latex exited with errors but SVG was produced")
	} else {
		j.SetDoneSVG(svgPath)
	}
}

func setDvisvgmEnv(cmd *exec.Cmd) {
	texDist := os.Getenv("TEXMFDIST")
	if texDist == "" {
		texDist = "/usr/local/texlive/2025basic/texmf-dist"
	}
	texCnf := os.Getenv("TEXMFCNF")
	if texCnf == "" {
		texCnf = texDist + "/web2c"
	}
	cmd.Env = append(os.Environ(), "TEXMFDIST="+texDist, "TEXMFCNF="+texCnf)
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func streamOutput(stdout, stderr io.Reader, logLines chan string, ctx context.Context) {
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			select {
			case logLines <- s.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			select {
			case logLines <- s.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
}
