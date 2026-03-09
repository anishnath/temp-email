package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"temp-email/internal/latex"
	"temp-email/internal/latex/compiler"
	"temp-email/internal/latex/filestore"
	"temp-email/internal/latex/job"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// LaTeX API handlers - served from main process.

func dedupeStrings(ss []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range ss {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func latexError(w http.ResponseWriter, errMsg, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}{Error: errMsg, Code: code})
}

// LaTeXCompileRequest is the JSON body for POST /api/latex/compile.
type LaTeXCompileRequest struct {
	Source  string   `json:"source"`
	FileIDs []string `json:"fileIds,omitempty"` // fileIds from upload API to include in job dir
}

// TikzCompileRequest is the JSON body for POST /api/latex/tikz/compile.
type TikzCompileRequest struct {
	Tikz          string   `json:"tikz,omitempty"` // inner tikzpicture content only
	Raw           string   `json:"raw,omitempty"`  // full paste from docs: \usetikzlibrary{...}\begin{tikzpicture}...\end{tikzpicture}
	FileIDs       []string `json:"fileIds,omitempty"`
	Border        string   `json:"border,omitempty"`        // reserved
	Packages      []string `json:"packages,omitempty"`      // extra \usepackage{pkg} (ignored when raw is used)
	TikzLibraries []string `json:"tikzLibraries,omitempty"` // extra \usetikzlibrary{lib} (merged when raw is used)
}

// LaTeXCompileResponse is the immediate response with jobId.
type LaTeXCompileResponse struct {
	JobID string `json:"jobId"`
}

// LaTeXStatusResponse is the job status response.
type LaTeXStatusResponse struct {
	JobID   string `json:"jobId"`
	Status  string `json:"status"`
	Warning string `json:"warning,omitempty"` // set when done but there were warnings (e.g. missing image)
	Error   string `json:"error,omitempty"`   // set when status=error, explains why compilation failed
}

// LaTeXUploadResponse is returned after successful upload.
type LaTeXUploadResponse struct {
	FileID   string `json:"fileId"`
	Filename string `json:"filename"`
}

// GetLaTeXCompile handles POST /api/latex/compile
func GetLaTeXCompile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		latexError(w, "method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		latexError(w, "failed to read body", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req LaTeXCompileRequest
	if err := json.Unmarshal(body, &req); err != nil {
		latexError(w, "invalid JSON", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	req.Source = strings.TrimSpace(req.Source)
	if req.Source == "" {
		latexError(w, "source is required", "BAD_REQUEST", http.StatusBadRequest)
		return
	}

	cfg := latex.LoadConfig()
	if int64(len(req.Source)) > cfg.MaxSourceSizeBytes {
		latexError(w, "source too large", "SOURCE_TOO_LARGE", http.StatusBadRequest)
		return
	}

	if err := compiler.Check(req.Source); err != nil {
		latexError(w, err.Error(), "SANITIZER_REJECTED", http.StatusBadRequest)
		return
	}

	j := job.NewCompileJob(req.Source, req.FileIDs)
	job.RegisterJob(j)
	latex.JobQueue <- j

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LaTeXCompileResponse{JobID: j.ID})
}

// PostTikzCompile handles POST /api/latex/tikz/compile
func PostTikzCompile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		latexError(w, "method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		latexError(w, "failed to read body", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req TikzCompileRequest
	if err := json.Unmarshal(body, &req); err != nil {
		latexError(w, "invalid JSON", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	req.Tikz = strings.TrimSpace(req.Tikz)
	req.Raw = strings.TrimSpace(req.Raw)

	if req.Raw == "" && req.Tikz == "" {
		latexError(w, "tikz or raw is required", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	if req.Raw != "" && req.Tikz != "" {
		latexError(w, "provide either tikz or raw, not both", "BAD_REQUEST", http.StatusBadRequest)
		return
	}

	cfg := latex.LoadConfig()
	sourceLen := int64(len(req.Tikz))
	if req.Raw != "" {
		sourceLen = int64(len(req.Raw))
	}
	if sourceLen > cfg.MaxSourceSizeBytes {
		latexError(w, "source too large", "SOURCE_TOO_LARGE", http.StatusBadRequest)
		return
	}

	var j *job.CompileJob
	if req.Raw != "" {
		parsed, err := compiler.ParseRaw(req.Raw)
		if err != nil {
			latexError(w, err.Error(), "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		// Merge parsed libs with any explicit tikzLibraries from request
		libs := append(parsed.TikzLibraries, req.TikzLibraries...)
		libs = dedupeStrings(libs)
		pkgs := append(parsed.Packages, req.Packages...)
		pkgs = dedupeStrings(pkgs)
		if err := compiler.ValidatePackageNames(pkgs, libs); err != nil {
			latexError(w, err.Error(), "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		if err := compiler.ValidateGDLibraryNames(parsed.GDLibraries); err != nil {
			latexError(w, err.Error(), "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		fullSource := "\\documentclass[dvisvgm]{minimal}\\usepackage{tikz}" + parsed.TikzBlock
		if err := compiler.Check(fullSource); err != nil {
			latexError(w, err.Error(), "SANITIZER_REJECTED", http.StatusBadRequest)
			return
		}
		j = job.NewTikzJobFromRaw(parsed.TikzBlock, req.FileIDs, pkgs, libs, parsed.GDLibraries)
	} else {
		if err := compiler.ValidatePackageNames(req.Packages, req.TikzLibraries); err != nil {
			latexError(w, err.Error(), "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		fullSource := "\\documentclass[dvisvgm]{minimal}\\usepackage{tikz}" + req.Tikz
		if err := compiler.Check(fullSource); err != nil {
			latexError(w, err.Error(), "SANITIZER_REJECTED", http.StatusBadRequest)
			return
		}
		j = job.NewTikzJob(req.Tikz, req.FileIDs, req.Packages, req.TikzLibraries)
	}
	job.RegisterJob(j)
	latex.JobQueue <- j

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LaTeXCompileResponse{JobID: j.ID})
}

// GetLaTeXJobStatus handles GET /api/latex/jobs/{jobId}/status
func GetLaTeXJobStatus(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["jobId"]
	if jobID == "" {
		latexError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}
	j, ok := job.GetJob(jobID)
	if !ok {
		latexError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}
	resp := LaTeXStatusResponse{JobID: j.ID, Status: string(j.GetStatus())}
	if j.GetStatus() == job.StatusDone && j.Error != "" {
		resp.Warning = j.Error
	}
	if j.GetStatus() == job.StatusError && j.Error != "" {
		resp.Error = j.Error
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// GetLaTeXJobPDF handles GET /api/latex/jobs/{jobId}/pdf
func GetLaTeXJobPDF(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["jobId"]
	if jobID == "" {
		latexError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}
	j, ok := job.GetJob(jobID)
	if !ok {
		latexError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}
	if j.GetStatus() != job.StatusDone {
		latexError(w, "PDF not ready", "PDF_NOT_READY", http.StatusNotFound)
		return
	}
	if j.PDFPath == "" {
		latexError(w, "PDF not found", "PDF_NOT_READY", http.StatusNotFound)
		return
	}
	f, err := os.Open(j.PDFPath)
	if err != nil {
		latexError(w, "failed to read PDF", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `inline; filename="document.pdf"`)
	http.ServeContent(w, r, "document.pdf", j.CreatedAt, f)
}

// GetLaTeXJobSVG handles GET /api/latex/jobs/{jobId}/svg (TikZ jobs only)
func GetLaTeXJobSVG(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["jobId"]
	if jobID == "" {
		latexError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}
	j, ok := job.GetJob(jobID)
	if !ok {
		latexError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}
	if j.GetStatus() != job.StatusDone {
		latexError(w, "SVG not ready", "SVG_NOT_READY", http.StatusNotFound)
		return
	}
	if j.SVGPath == "" {
		latexError(w, "SVG not found", "SVG_NOT_READY", http.StatusNotFound)
		return
	}
	f, err := os.Open(j.SVGPath)
	if err != nil {
		latexError(w, "failed to read SVG", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Content-Disposition", `inline; filename="document.svg"`)
	http.ServeContent(w, r, "document.svg", j.CreatedAt, f)
}

// GetLaTeXJobLogs handles GET /api/latex/jobs/{jobId}/logs (SSE)
func GetLaTeXJobLogs(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["jobId"]
	if jobID == "" {
		latexError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}
	j, ok := job.GetJob(jobID)
	if !ok {
		latexError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		latexError(w, "streaming not supported", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	sendLine := func(evt map[string]string) bool {
		b, _ := json.Marshal(evt)
		if _, err := w.Write([]byte("data: " + string(b) + "\n\n")); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	for {
		select {
		case <-r.Context().Done():
			log.Printf("client disconnected from latex logs: %s", r.RemoteAddr)
			return
		case line, ok := <-j.LogLines:
			if !ok {
				status := j.GetStatus()
				switch status {
				case job.StatusDone:
					evt := map[string]string{"status": "done"}
					if j.SVGPath != "" {
						evt["svgUrl"] = "/api/latex/jobs/" + jobID + "/svg"
					} else {
						evt["pdfUrl"] = "/api/latex/jobs/" + jobID + "/pdf"
					}
					if j.Error != "" {
						evt["warning"] = j.Error
					}
					sendLine(evt)
				case job.StatusError:
					sendLine(map[string]string{"status": "error", "message": j.Error})
				default:
					sendLine(map[string]string{"status": string(status), "message": j.Error})
				}
				flusher.Flush()
				return
			}
			if !sendLine(map[string]string{"line": line}) {
				return
			}
		}
	}
}

// GetLaTeXUpload handles POST /api/latex/upload
func GetLaTeXUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		latexError(w, "method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		latexError(w, "failed to parse multipart form", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		latexError(w, "missing or invalid file field", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileID := uuid.New().String()
	filename := header.Filename
	if filename == "" {
		filename = "upload"
	}
	cfg := latex.LoadConfig()
	baseDir := cfg.LatexTempDir + "/uploads"
	uploadDir := filepath.Join(baseDir, fileID)
	if err := os.MkdirAll(uploadDir, 0750); err != nil {
		latexError(w, "failed to create upload directory", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	targetPath := filepath.Join(uploadDir, filename)
	out, err := os.Create(targetPath)
	if err != nil {
		latexError(w, "failed to create file", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		latexError(w, "failed to write file", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	// Schedule cleanup of upload dir after configured duration
	cleanupAfter := cfg.CleanupAfter
	if v := os.Getenv("LATEX_UPLOAD_CLEANUP_MINUTES"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			cleanupAfter = time.Duration(n) * time.Minute
		}
	}
	filestore.ScheduleUploadCleanup(fileID, cleanupAfter)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(LaTeXUploadResponse{FileID: fileID, Filename: filename})
}
