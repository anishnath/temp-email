package api

import (
	"encoding/json"
	"log"
	"net/http"

	"latex-api/internal/model"
)

func HandleJobLogs(w http.ResponseWriter, r *http.Request, jobID string) {
	job, ok := model.GetJob(jobID)
	if !ok {
		writeError(w, "job not found", "JOB_NOT_FOUND", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, "streaming not supported", "INTERNAL_ERROR", http.StatusInternalServerError)
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
			log.Printf("client disconnected from logs stream: %s", r.RemoteAddr)
			return
		case line, ok := <-job.LogLines:
			if !ok {
				status := job.GetStatus()
				switch status {
				case model.StatusDone:
					sendLine(map[string]string{"status": "done", "pdfUrl": "/api/jobs/" + jobID + "/pdf"})
				case model.StatusError:
					sendLine(map[string]string{"status": "error", "message": job.Error})
				default:
					sendLine(map[string]string{"status": string(status), "message": job.Error})
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
