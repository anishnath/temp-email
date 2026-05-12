package compiler

import (
	"context"
	"fmt"
	"log"
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

	// Run latex — single CombinedOutput (no extra goroutines / WaitGroup).
	latexCmd := exec.CommandContext(ctx, "latex", "-interaction=nonstopmode", "document.tex")
	latexCmd.Dir = workDir
	setDvisvgmEnv(latexCmd)
	log.Printf("tikz job_id=%s running latex dir=%s args=%v", j.ID, workDir, latexCmd.Args)

	latexOut, latexErr := latexCmd.CombinedOutput()
	tikzPushLogLines(j.LogLines, string(latexOut))

	dviPath := filepath.Join(workDir, "document.dvi")
	if _, err := os.Stat(dviPath); err != nil {
		j.SetError(summarizeTikzLatexFailure(workDir, latexErr, latexOut))
		return
	}

	// Run dvisvgm
	svgPath := filepath.Join(workDir, "document.svg")
	dvisvgmCmd := exec.CommandContext(ctx, "dvisvgm", "--no-fonts", "-o", "document.svg", "document.dvi")
	dvisvgmCmd.Dir = workDir
	setDvisvgmEnv(dvisvgmCmd)
	log.Printf("tikz job_id=%s running dvisvgm dir=%s args=%v", j.ID, workDir, dvisvgmCmd.Args)

	dvisvgmOut, err := dvisvgmCmd.CombinedOutput()
	tikzPushLogLines(j.LogLines, string(dvisvgmOut))
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

func tikzPushLogLines(ch chan string, blob string) {
	for _, line := range strings.Split(blob, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		select {
		case ch <- line:
		default:
		}
	}
}

func summarizeTikzLatexFailure(workDir string, latexErr error, latexOut []byte) string {
	detail := SummarizeDocumentLog(workDir)
	if strings.HasPrefix(detail, "could not read document.log") {
		if out := strings.TrimSpace(string(latexOut)); out != "" {
			detail = detail + "\n--- latex stdout/stderr ---\n" + trimLatexSummary(out)
		} else {
			detail = detail + " (no latex output; check latex/DVI install and TEXMFDIST)"
		}
	}
	if latexErr != nil {
		return "latex failed: " + latexErr.Error() + " | " + detail
	}
	return "DVI was not produced | " + detail
}
