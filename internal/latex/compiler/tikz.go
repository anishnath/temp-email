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
	"sync"
	"time"

	"temp-email/internal/latex/filestore"
	"temp-email/internal/latex/job"
)

// TikZ document template using dvisvgm class for clean SVG output.
// {{PACKAGES}} is replaced with user \usepackage{} and \usetikzlibrary{} lines.
// {{TIKZ_BLOCK}} is either the full \begin{tikzpicture}...\end{tikzpicture} (from raw) or \begin{tikzpicture}\n{{TIKZ}}\n\end{tikzpicture}.
//
// tikzDefaultLibraries is preloaded for typical math/physics/chemistry diagrams, circuits,
// CV/flow layouts, and lecture figures. Intentionally omits graphdrawing and external.
const tikzDefaultLibraries = "arrows,arrows.meta,bending,positioning,calc,scopes,fit,backgrounds," +
	"shapes.geometric,shapes.misc,shapes.symbols,shapes.multipart,shapes.arrows,shapes.callouts," +
	"shapes.gates.logic.US,shapes.gates.logic.IEC," +
	"trees,chains,matrix,mindmap,automata,graphs," +
	"decorations.pathmorphing,decorations.pathreplacing,decorations.markings,decorations.shapes,decorations.text,decorations.fractals," +
	"patterns,patterns.meta,intersections,angles,quotes,through," +
	"circuits.ee.IEC,circuits.logic.US,circuits.logic.IEC," +
	"fadings,shadows,spy,lindenmayersystems," +
	"datavisualization,plotmarks,calendar," +
	"er,petri,folding,fixedpointarithmetic,fpu,svg.path"

const tikzTemplate = `\documentclass[dvisvgm]{article}
\usepackage{tikz}
\usetikzlibrary{` + tikzDefaultLibraries + `}
{{PACKAGES}}
\pagestyle{empty}

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
		// Include any preamble (e.g. \tikzset{...}) that appears before \begin{tikzpicture}
		stripped := reStripPreamble.ReplaceAllString(raw, "")
		if idx := strings.Index(stripped, "\\begin{tikzpicture}"); idx > 0 {
			prefix := strings.TrimSpace(stripped[:idx])
			if prefix != "" {
				tikzBlock = prefix + "\n\n" + tikzBlock
			}
		}
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

	var tail latexStreamTail
	tail.maxLines = 200
	var drainWG sync.WaitGroup
	drainWG.Add(2)
	go drainLatexPipe(stdout, &drainWG, j.LogLines, ctx, &tail)
	go drainLatexPipe(stderr, &drainWG, j.LogLines, ctx, &tail)

	latexErr := latexCmd.Wait()
	drainWG.Wait()

	dviPath := filepath.Join(workDir, "document.dvi")
	if _, err := os.Stat(dviPath); err != nil {
		j.SetError(formatLatexRunFailure(workDir, latexErr, &tail))
		return
	}

	// Run dvisvgm (even if latex exited non-zero, DVI may be usable)
	svgPath := filepath.Join(workDir, "document.svg")
	dvisvgmCmd := exec.CommandContext(ctx, "dvisvgm", "--no-fonts", "-o", "document.svg", "document.dvi")
	dvisvgmCmd.Dir = workDir
	setDvisvgmEnv(dvisvgmCmd)

	dvisvgmOut, err := dvisvgmCmd.CombinedOutput()
	if err != nil {
		j.SetError(formatDvisvgmFailure(err, dvisvgmOut))
		return
	}

	if _, err := os.Stat(svgPath); err != nil {
		j.SetError("SVG was not produced (" + svgPath + "): " + err.Error())
		return
	}

	if latexErr != nil {
		j.SetDoneSVGWithWarning(svgPath, "latex exited with errors but SVG was produced")
	} else {
		j.SetDoneSVG(svgPath)
	}
}

// texDistDefaults are fallback TEXMFDIST paths when env is unset (Linux vs macOS).
var texDistDefaults = []string{
	"/usr/share/texlive/texmf-dist", // Debian/Ubuntu
	"/usr/share/texmf-dist",
	"/usr/local/texlive/2026/texmf-dist",
	"/usr/local/texlive/2025/texmf-dist",
	"/usr/local/texlive/2025basic/texmf-dist",
	"/usr/local/texlive/2024/texmf-dist",
	"/usr/local/texlive/2024basic/texmf-dist",
	"/usr/local/texlive/2023/texmf-dist",
}

func setDvisvgmEnv(cmd *exec.Cmd) {
	texDist := os.Getenv("TEXMFDIST")
	if texDist == "" {
		for _, p := range texDistDefaults {
			if _, err := os.Stat(p); err == nil {
				texDist = p
				break
			}
		}
		if texDist == "" {
			if p := texmfDistFromKpsewhich(); p != "" {
				texDist = p
			}
		}
		if texDist == "" {
			texDist = texDistDefaults[0] // use Linux path as last resort
		}
	}
	texCnf := os.Getenv("TEXMFCNF")
	if texCnf == "" {
		texCnf = texDist + "/web2c"
	}
	cmd.Env = append(os.Environ(), "TEXMFDIST="+texDist, "TEXMFCNF="+texCnf)
}

// texmfDistFromKpsewhich returns TEXMFDIST when kpsewhich is on PATH (works for nonstandard TeX installs).
func texmfDistFromKpsewhich() string {
	out, err := exec.Command("kpsewhich", "-var-value=TEXMFDIST").Output()
	if err != nil {
		return ""
	}
	p := strings.TrimSpace(string(out))
	if p == "" {
		return ""
	}
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

func formatDvisvgmFailure(err error, out []byte) string {
	var b strings.Builder
	b.WriteString("dvisvgm failed")
	if err != nil {
		b.WriteString(": ")
		b.WriteString(err.Error())
	}
	s := strings.TrimSpace(string(out))
	if s != "" {
		b.WriteString(" | ")
		b.WriteString(trimLatexSummary(s))
	} else if err != nil {
		b.WriteString(" | (no stdout/stderr; check that dvisvgm is installed and on PATH for the service user, and that TEXMFDIST/TEXMFCNF match your TeX tree)")
	}
	return b.String()
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// latexStreamTail keeps recent stdout/stderr lines when document.log is missing (e.g. format file not found).
type latexStreamTail struct {
	mu       sync.Mutex
	lines    []string
	maxLines int
}

func (t *latexStreamTail) push(line string) {
	if t == nil || t.maxLines <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = append(t.lines, line)
	if len(t.lines) > t.maxLines {
		t.lines = t.lines[len(t.lines)-t.maxLines:]
	}
}

func (t *latexStreamTail) text() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.Join(t.lines, "\n")
}

func drainLatexPipe(r io.Reader, wg *sync.WaitGroup, logLines chan string, ctx context.Context, tail *latexStreamTail) {
	defer wg.Done()
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		line := s.Text()
		tail.push(line)
		select {
		case logLines <- line:
		case <-ctx.Done():
			return
		}
	}
}

func formatLatexRunFailure(workDir string, latexErr error, tail *latexStreamTail) string {
	detail := SummarizeDocumentLog(workDir)
	if strings.HasPrefix(detail, "could not read document.log") {
		if out := strings.TrimSpace(tail.text()); out != "" {
			detail = detail + "\n--- latex stdout/stderr (tail) ---\n" + trimLatexSummary(out)
		} else {
			detail = detail + " (no stdout/stderr captured). Hint: install TeX Live's latex/DVI engine (latex.fmt), set TEXMFDIST to your tree's texmf-dist, or run `kpsewhich -var-value=TEXMFDIST` on the host."
		}
	}
	if latexErr != nil {
		return "latex failed: " + latexErr.Error() + " | " + detail
	}
	return "DVI was not produced | " + detail
}
