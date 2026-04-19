package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"latex-api/config"
	"latex-api/internal/compiler"
	"latex-api/internal/model"
	"latex-api/queue"
)

// CompileRequest is the JSON body for POST /api/compile.
type CompileRequest struct {
	Source  string   `json:"source"`
	FileIDs []string `json:"fileIds"`
}

// CompileResponse is the immediate response with jobId.
type CompileResponse struct {
	JobID string `json:"jobId"`
}

func HandleCompile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, "failed to read body", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req CompileRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, "invalid JSON", "BAD_REQUEST", http.StatusBadRequest)
		return
	}

	req.Source = strings.TrimSpace(req.Source)
	if req.Source == "" {
		writeError(w, "source is required", "BAD_REQUEST", http.StatusBadRequest)
		return
	}

	cfg := config.Load()
	if int64(len(req.Source)) > cfg.MaxSourceSizeBytes {
		writeError(w, "source too large", "SOURCE_TOO_LARGE", http.StatusBadRequest)
		return
	}

	if err := compiler.Check(req.Source); err != nil {
		writeError(w, err.Error(), "SANITIZER_REJECTED", http.StatusBadRequest)
		return
	}

	job := model.NewCompileJob(req.Source, req.FileIDs)
	model.RegisterJob(job)
	queue.JobQueue <- job

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(CompileResponse{JobID: job.ID})
}
