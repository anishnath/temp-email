package api

import (
	"net/http"
)

// RegisterRoutes sets up all API routes on mux. Requires Go 1.22+ for path parameters.
// Paths are registered twice: short (/api/...) and Java-client (/api/latex/...) forms.
func RegisterRoutes(mux *http.ServeMux) {
	register := func(pattern string, handler http.HandlerFunc) {
		mux.HandleFunc(pattern, handler)
	}

	register("POST /api/compile", HandleCompile)
	register("POST /api/latex/compile", HandleCompile)
	register("POST /api/upload", HandleUpload)
	register("POST /api/latex/upload", HandleUpload)
	register("GET /api/jobs/{jobId}/status", handleJobStatus)
	register("GET /api/latex/jobs/{jobId}/status", handleJobStatus)
	register("GET /api/jobs/{jobId}/pdf", handleJobPDF)
	register("GET /api/latex/jobs/{jobId}/pdf", handleJobPDF)
	register("GET /api/jobs/{jobId}/logs", handleJobLogs)
	register("GET /api/latex/jobs/{jobId}/logs", handleJobLogs)
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
