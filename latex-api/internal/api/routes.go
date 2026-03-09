package api

import (
	"net/http"
)

// RegisterRoutes sets up all API routes on mux. Requires Go 1.22+ for path parameters.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/compile", HandleCompile)
	mux.HandleFunc("POST /api/upload", HandleUpload)
	mux.HandleFunc("GET /api/jobs/{jobId}/status", handleJobStatus)
	mux.HandleFunc("GET /api/jobs/{jobId}/pdf", handleJobPDF)
	mux.HandleFunc("GET /api/jobs/{jobId}/logs", handleJobLogs)
}

func handleJobStatus(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("jobId")
	if jobID == "" {
		writeError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}
	HandleJobStatus(w, r, jobID)
}

func handleJobPDF(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("jobId")
	if jobID == "" {
		writeError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}
	HandleJobPDF(w, r, jobID)
}

func handleJobLogs(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("jobId")
	if jobID == "" {
		writeError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}
	HandleJobLogs(w, r, jobID)
}
