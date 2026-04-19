package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"latex-api/internal/model"
	"latex-api/queue"
)

func init() {
	queue.StartWorkerPool(2)
}

func TestHandleCompile_BadJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/compile", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HandleCompile(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d", w.Code)
	}
}

func TestHandleCompile_SanitizerRejects(t *testing.T) {
	body := `{"source": "\\write18{ls}"}`
	req := httptest.NewRequest("POST", "/api/compile", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HandleCompile(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "SANITIZER_REJECTED" {
		t.Errorf("got code %q", resp.Code)
	}
}

func TestHandleCompile_Success(t *testing.T) {
	source := `\documentclass{article}\begin{document}Hello\end{document}`
	body, _ := json.Marshal(map[string]string{"source": source})
	req := httptest.NewRequest("POST", "/api/compile", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HandleCompile(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("got status %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		JobID string `json:"jobId"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.JobID == "" {
		t.Error("expected non-empty jobId")
	}
}

func TestHandleJobStatus_NotFound(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/jobs/nonexistent/status", nil)
	w := httptest.NewRecorder()
	HandleJobStatus(w, req, "nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("got status %d", w.Code)
	}
}

func TestHandleJobStatus_Found(t *testing.T) {
	job := model.NewCompileJob("x", nil)
	model.RegisterJob(job)

	req := httptest.NewRequest("GET", "/api/jobs/"+job.ID+"/status", nil)
	w := httptest.NewRecorder()
	HandleJobStatus(w, req, job.ID)
	if w.Code != http.StatusOK {
		t.Errorf("got status %d", w.Code)
	}
	var resp StatusResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.JobID != job.ID || resp.Status != "pending" {
		t.Errorf("got %+v", resp)
	}
}
