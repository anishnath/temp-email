package api

import (
	"net/http"
	"os"

	"latex-api/internal/model"
)

func HandleJobPDF(w http.ResponseWriter, r *http.Request, jobID string) {
	job, ok := model.GetJob(jobID)
	if !ok {
		writeError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}

	if job.GetStatus() != model.StatusDone {
		writeError(w, "PDF not ready", "PDF_NOT_READY", http.StatusNotFound)
		return
	}

	if job.PDFPath == "" {
		writeError(w, "PDF not found", "PDF_NOT_READY", http.StatusNotFound)
		return
	}

	f, err := os.Open(job.PDFPath)
	if err != nil {
		writeError(w, "failed to read PDF", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `inline; filename="document.pdf"`)

	http.ServeContent(w, r, "document.pdf", job.CreatedAt, f)
}
