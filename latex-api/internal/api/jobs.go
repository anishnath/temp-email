package api

import (
	"encoding/json"
	"net/http"

	"latex-api/internal/model"
)

// StatusResponse is the job status response.
type StatusResponse struct {
	JobID  string `json:"jobId"`
	Status string `json:"status"`
}

func HandleJobStatus(w http.ResponseWriter, r *http.Request, jobID string) {
	job, ok := model.GetJob(jobID)
	if !ok {
		writeError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(StatusResponse{
		JobID:  job.ID,
		Status: string(job.GetStatus()),
	})
}
