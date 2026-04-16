package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// minimalLHR is a trimmed Lighthouse Result JSON that exercises every code
// path in buildLighthouseResult without needing a real Chrome process.
const minimalLHR = `{
  "categories": {
    "performance": {
      "score": 0.72,
      "auditRefs": [
        {"id": "first-contentful-paint"},
        {"id": "largest-contentful-paint"},
        {"id": "uses-https"},
        {"id": "meta-description"}
      ]
    },
    "seo": {
      "score": 0.98,
      "auditRefs": [
        {"id": "meta-description"},
        {"id": "document-title"}
      ]
    },
    "accessibility": {
      "score": 0.91,
      "auditRefs": [
        {"id": "image-alt"}
      ]
    },
    "best-practices": {
      "score": 0.83,
      "auditRefs": [
        {"id": "uses-https"}
      ]
    }
  },
  "audits": {
    "first-contentful-paint": {
      "id":               "first-contentful-paint",
      "title":            "First Contentful Paint",
      "description":      "FCP marks the first text/image painted.",
      "score":            0.8,
      "scoreDisplayMode": "numeric",
      "displayValue":     "1.2 s"
    },
    "largest-contentful-paint": {
      "id":               "largest-contentful-paint",
      "title":            "Largest Contentful Paint",
      "description":      "LCP marks the largest text/image painted.",
      "score":            0.6,
      "scoreDisplayMode": "numeric",
      "displayValue":     "3.1 s"
    },
    "uses-https": {
      "id":               "uses-https",
      "title":            "Uses HTTPS",
      "description":      "All sites should be protected with HTTPS.",
      "score":            1,
      "scoreDisplayMode": "binary",
      "displayValue":     ""
    },
    "meta-description": {
      "id":               "meta-description",
      "title":            "Document has a meta description",
      "description":      "Meta descriptions may be included in search results.",
      "score":            1,
      "scoreDisplayMode": "binary",
      "displayValue":     ""
    },
    "document-title": {
      "id":               "document-title",
      "title":            "Document has a title element",
      "description":      "The title gives screen-reader users an overview.",
      "score":            1,
      "scoreDisplayMode": "binary",
      "displayValue":     ""
    },
    "image-alt": {
      "id":               "image-alt",
      "title":            "Image elements have alt attributes",
      "description":      "Informative elements should aim for short, descriptive alt text.",
      "score":            0,
      "scoreDisplayMode": "binary",
      "displayValue":     "3 elements found"
    },
    "server-response-time": {
      "id":               "server-response-time",
      "title":            "Server response times are fast (TTFB)",
      "description":      "TTFB is the time taken for the browser to receive the first byte.",
      "score":            0.95,
      "scoreDisplayMode": "numeric",
      "displayValue":     "120 ms"
    }
  }
}`

// setupLhTest creates an isolated SQLite DB for the test, injects a fake
// lighthouse binary, and resets all shared global state.
func setupLhTest(t *testing.T) func() {
	t.Helper()

	// Reset DB state
	lhDBMu.Lock()
	if lhDB != nil {
		lhDB.Close()
		lhDB = nil
	}
	lhDBMu.Unlock()

	// Reset worker state so each test gets fresh workers with the right DB.
	lhWorkerMu.Lock()
	lhWorkerStarted = false
	lhJobQueue = nil
	lhWorkerMu.Unlock()

	tmp := t.TempDir()
	t.Setenv("LIGHTHOUSE_DB_PATH", filepath.Join(tmp, "lh_test.sqlite"))
	t.Setenv("LIGHTHOUSE_WORKERS", "1")
	t.Setenv("LIGHTHOUSE_QUEUE_SIZE", "10")

	// Fake lighthouse binary: prints minimalLHR to stdout
	fakeBin := filepath.Join(tmp, "lighthouse")
	script := "#!/bin/sh\ncat <<'LHEOF'\n" + minimalLHR + "\nLHEOF\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake lighthouse: %v", err)
	}
	t.Setenv("LIGHTHOUSE_CMD", fakeBin)

	return func() {
		lhDBMu.Lock()
		if lhDB != nil {
			lhDB.Close()
			lhDB = nil
		}
		lhDBMu.Unlock()
	}
}

// processJobSync inserts a job directly and calls processLighthouseJob
// synchronously, bypassing the async queue. Used to test job processing
// without racing against background goroutines.
func processJobSync(t *testing.T, url, strategy string, cats []string) (jobID, auditID int64) {
	t.Helper()
	if err := initLhDB(); err != nil {
		t.Fatalf("initLhDB: %v", err)
	}
	createdAt := time.Now().UTC().Format(time.RFC3339)
	res, err := lhDB.Exec(
		`INSERT INTO lighthouse_jobs (status, url, strategy, categories, created_at)
		 VALUES ('queued', ?, ?, ?, ?)`,
		url, strategy, strings.Join(cats, ","), createdAt,
	)
	if err != nil {
		t.Fatalf("insert job: %v", err)
	}
	jobID, _ = res.LastInsertId()
	processLighthouseJob(jobID) // synchronous — fake binary exits instantly

	var aid sql.NullInt64
	lhDB.QueryRow(`SELECT audit_id FROM lighthouse_jobs WHERE id=?`, jobID).Scan(&aid)
	auditID = aid.Int64
	return
}

// ── POST /api/lighthouse ──────────────────────────────────────────────────────

func TestPostLighthouse_returnsAccepted(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	body := `{"url":"https://example.com","strategy":"mobile"}`
	req := httptest.NewRequest(http.MethodPost, "/api/lighthouse", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	PostLighthouse(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp lighthouseJobResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.JobID == 0 {
		t.Error("job_id should be non-zero")
	}
	if resp.Status != "queued" {
		t.Errorf("status: want 'queued', got %q", resp.Status)
	}
	if resp.URL != "https://example.com" {
		t.Errorf("url mismatch: %q", resp.URL)
	}
	if resp.Strategy != "mobile" {
		t.Errorf("strategy mismatch: %q", resp.Strategy)
	}
}

func TestPostLighthouse_missingURL(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/api/lighthouse",
		bytes.NewBufferString(`{"strategy":"mobile"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	PostLighthouse(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

func TestPostLighthouse_invalidJSON(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/api/lighthouse",
		bytes.NewBufferString(`not-json`))
	rr := httptest.NewRecorder()
	PostLighthouse(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

// ── processLighthouseJob (synchronous) ───────────────────────────────────────

func TestProcessLighthouseJob_scores(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	_, auditID := processJobSync(t, "https://example.com", "mobile",
		[]string{"performance", "seo", "accessibility", "best-practices"})

	if auditID == 0 {
		t.Fatal("audit_id should be non-zero after processing")
	}
	result := lhLoadAudit(auditID)
	if result == nil {
		t.Fatal("lhLoadAudit returned nil")
	}
	if result.Scores.Performance == nil || *result.Scores.Performance != 72 {
		t.Errorf("performance: want 72, got %v", result.Scores.Performance)
	}
	if result.Scores.SEO == nil || *result.Scores.SEO != 98 {
		t.Errorf("seo: want 98, got %v", result.Scores.SEO)
	}
	if result.Scores.Accessibility == nil || *result.Scores.Accessibility != 91 {
		t.Errorf("accessibility: want 91, got %v", result.Scores.Accessibility)
	}
	if result.Scores.BestPractices == nil || *result.Scores.BestPractices != 83 {
		t.Errorf("best_practices: want 83, got %v", result.Scores.BestPractices)
	}
}

func TestProcessLighthouseJob_coreWebVitals(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	_, auditID := processJobSync(t, "https://example.com", "mobile",
		[]string{"performance", "seo", "accessibility", "best-practices"})

	result := lhLoadAudit(auditID)
	if result == nil {
		t.Fatal("lhLoadAudit returned nil")
	}
	if result.CoreWebVitals["FCP"] != "1.2 s" {
		t.Errorf("FCP: want '1.2 s', got %q", result.CoreWebVitals["FCP"])
	}
	if result.CoreWebVitals["LCP"] != "3.1 s" {
		t.Errorf("LCP: want '3.1 s', got %q", result.CoreWebVitals["LCP"])
	}
	if result.CoreWebVitals["TTFB"] != "120 ms" {
		t.Errorf("TTFB: want '120 ms', got %q", result.CoreWebVitals["TTFB"])
	}
}

func TestProcessLighthouseJob_failedPassedAudits(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	_, auditID := processJobSync(t, "https://example.com", "mobile",
		[]string{"performance", "seo", "accessibility", "best-practices"})

	result := lhLoadAudit(auditID)
	if result == nil {
		t.Fatal("lhLoadAudit returned nil")
	}

	failedIDs := map[string]bool{}
	for _, a := range result.FailedAudits {
		failedIDs[a.ID] = true
	}
	for _, want := range []string{"image-alt", "largest-contentful-paint"} {
		if !failedIDs[want] {
			t.Errorf("expected %q in failed_audits", want)
		}
	}

	passedIDs := map[string]int{}
	for _, a := range result.PassedAudits {
		passedIDs[a.ID]++
	}
	if passedIDs["uses-https"] != 1 {
		t.Errorf("uses-https should appear exactly once in passed_audits, got %d", passedIDs["uses-https"])
	}
	if failedIDs["uses-https"] {
		t.Error("uses-https should NOT be in failed_audits")
	}
}

// ── GET /api/lighthouse/jobs/{id} ────────────────────────────────────────────

func TestGetLighthouseJob_done(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	jobID, auditID := processJobSync(t, "https://example.com", "desktop",
		[]string{"performance", "seo"})

	req := httptest.NewRequest(http.MethodGet, "/api/lighthouse/jobs/"+itoa(jobID), nil)
	req = mux.SetURLVars(req, map[string]string{"id": itoa(jobID)})
	rr := httptest.NewRecorder()
	GetLighthouseJob(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var job lighthouseJobStatus
	json.NewDecoder(rr.Body).Decode(&job)

	if job.Status != "done" {
		t.Errorf("status: want 'done', got %q", job.Status)
	}
	if job.Result == nil {
		t.Fatal("result should be populated for done job")
	}
	if job.Result.AuditID != auditID {
		t.Errorf("audit_id mismatch: want %d, got %d", auditID, job.Result.AuditID)
	}
	if job.Result.Strategy != "desktop" {
		t.Errorf("strategy: want 'desktop', got %q", job.Result.Strategy)
	}
	if job.Result.Scores.Performance == nil || *job.Result.Scores.Performance != 72 {
		t.Errorf("performance score: %v", job.Result.Scores.Performance)
	}
}

func TestGetLighthouseJob_notFound(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()
	if err := initLhDB(); err != nil {
		t.Fatalf("initLhDB: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/lighthouse/jobs/9999", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "9999"})
	rr := httptest.NewRecorder()
	GetLighthouseJob(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rr.Code)
	}
}

func TestGetLighthouseJob_invalidID(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/lighthouse/jobs/abc", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "abc"})
	rr := httptest.NewRecorder()
	GetLighthouseJob(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

// ── GET /api/lighthouse/audits ───────────────────────────────────────────────

func TestGetLighthouseAudits_empty(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	if err := initLhDB(); err != nil {
		t.Fatalf("initLhDB: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/lighthouse/audits", nil)
	rr := httptest.NewRecorder()
	GetLighthouseAudits(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp struct {
		Count  int                  `json:"count"`
		Audits []lighthouseListItem `json:"audits"`
	}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Count != 0 || len(resp.Audits) != 0 {
		t.Errorf("want empty list, got count=%d", resp.Count)
	}
}

func TestGetLighthouseAudits_afterProcess(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	processJobSync(t, "https://example.com", "mobile",
		[]string{"performance", "seo", "accessibility", "best-practices"})
	processJobSync(t, "https://other.com", "desktop",
		[]string{"performance", "seo", "accessibility", "best-practices"})

	// List all
	req := httptest.NewRequest(http.MethodGet, "/api/lighthouse/audits", nil)
	rr := httptest.NewRecorder()
	GetLighthouseAudits(rr, req)

	var resp struct {
		Count  int                  `json:"count"`
		Audits []lighthouseListItem `json:"audits"`
	}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Count != 2 {
		t.Errorf("want count=2, got %d", resp.Count)
	}

	// Filter by URL
	req2 := httptest.NewRequest(http.MethodGet,
		"/api/lighthouse/audits?url=https://example.com", nil)
	rr2 := httptest.NewRecorder()
	GetLighthouseAudits(rr2, req2)

	var resp2 struct {
		Count  int                  `json:"count"`
		Audits []lighthouseListItem `json:"audits"`
	}
	json.NewDecoder(rr2.Body).Decode(&resp2)
	if resp2.Count != 1 {
		t.Errorf("url filter: want count=1, got %d", resp2.Count)
	}
	if len(resp2.Audits) > 0 && resp2.Audits[0].URL != "https://example.com" {
		t.Errorf("url filter: wrong url %q", resp2.Audits[0].URL)
	}
}

// ── GET /api/lighthouse/audits/{id} ─────────────────────────────────────────

func TestGetLighthouseAuditByID_roundtrip(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	_, auditID := processJobSync(t, "https://example.com", "desktop",
		[]string{"performance", "seo", "accessibility", "best-practices"})

	if auditID == 0 {
		t.Fatal("auditID is 0 after processing")
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/lighthouse/audits/"+itoa(auditID), nil)
	getReq = mux.SetURLVars(getReq, map[string]string{"id": itoa(auditID)})
	getRR := httptest.NewRecorder()
	GetLighthouseAuditByID(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", getRR.Code, getRR.Body.String())
	}
	var fetched lighthouseResult
	json.NewDecoder(getRR.Body).Decode(&fetched)

	if fetched.AuditID != auditID {
		t.Errorf("audit_id mismatch: want %d, got %d", auditID, fetched.AuditID)
	}
	if fetched.URL != "https://example.com" {
		t.Errorf("url mismatch: %q", fetched.URL)
	}
	if fetched.Strategy != "desktop" {
		t.Errorf("strategy mismatch: %q", fetched.Strategy)
	}
	if fetched.Scores.Performance == nil || *fetched.Scores.Performance != 72 {
		t.Errorf("performance score not preserved: %v", fetched.Scores.Performance)
	}
	if len(fetched.FailedAudits) == 0 {
		t.Error("failed_audits should not be empty after round-trip")
	}
	if len(fetched.PassedAudits) == 0 {
		t.Error("passed_audits should not be empty after round-trip")
	}
}

func TestGetLighthouseAuditByID_notFound(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()
	if err := initLhDB(); err != nil {
		t.Fatalf("initLhDB: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/lighthouse/audits/9999", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "9999"})
	rr := httptest.NewRecorder()
	GetLighthouseAuditByID(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rr.Code)
	}
}

func TestGetLighthouseAuditByID_invalidID(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/lighthouse/audits/abc", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "abc"})
	rr := httptest.NewRecorder()
	GetLighthouseAuditByID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rr.Code)
	}
}

// ── buildLighthouseResult unit tests ────────────────────────────────────────

func TestBuildLighthouseResult_deduplication(t *testing.T) {
	var lhr lhJSON
	if err := json.Unmarshal([]byte(minimalLHR), &lhr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	cats := []string{"performance", "seo", "accessibility", "best-practices"}
	result := buildLighthouseResult("https://example.com", "mobile", cats, lhr)

	idCount := map[string]int{}
	for _, a := range result.FailedAudits {
		idCount[a.ID]++
	}
	for _, a := range result.PassedAudits {
		idCount[a.ID]++
	}
	for id, count := range idCount {
		if count > 1 {
			t.Errorf("audit %q appears %d times (want 1) — deduplication broken", id, count)
		}
	}
}

func TestBuildLighthouseResult_strategyPreserved(t *testing.T) {
	var lhr lhJSON
	json.Unmarshal([]byte(minimalLHR), &lhr)

	r := buildLighthouseResult("https://x.com", "desktop", []string{"performance"}, lhr)
	if r.Strategy != "desktop" {
		t.Errorf("strategy not preserved: %q", r.Strategy)
	}
}

// ── DB helpers ────────────────────────────────────────────────────────────────

func TestSaveLighthouseResult_persistsAndLoads(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	if err := initLhDB(); err != nil {
		t.Fatalf("initLhDB: %v", err)
	}

	perf := 88
	seo := 95
	r := lighthouseResult{
		URL:        "https://persist-test.com",
		Strategy:   "mobile",
		Categories: []string{"performance", "seo"},
		FetchedAt:  "2026-01-01T00:00:00Z",
		Scores: lighthouseScores{
			Performance: &perf,
			SEO:         &seo,
		},
		FailedAudits: []lighthouseAudit{{ID: "image-alt", Title: "Image alt", Score: ptrF(0.0)}},
		PassedAudits: []lighthouseAudit{{ID: "uses-https", Title: "Uses HTTPS", Score: ptrF(1.0)}},
	}

	id := saveLighthouseResult(r)
	if id == 0 {
		t.Fatal("saveLighthouseResult returned 0")
	}

	var url, strategy string
	var sp, ss sql.NullInt64
	err := lhDB.QueryRow(
		`SELECT url, strategy, score_performance, score_seo FROM lighthouse_audits WHERE id=?`, id,
	).Scan(&url, &strategy, &sp, &ss)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if url != "https://persist-test.com" {
		t.Errorf("url: %q", url)
	}
	if !sp.Valid || sp.Int64 != 88 {
		t.Errorf("score_performance: %v", sp)
	}
	if !ss.Valid || ss.Int64 != 95 {
		t.Errorf("score_seo: %v", ss)
	}
}

// ── tiny helpers ──────────────────────────────────────────────────────────────

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}

func ptrF(f float64) *float64 { return &f }
