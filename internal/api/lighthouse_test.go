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

// setupLhTest creates an isolated in-memory SQLite DB for the test, injects a
// fake lighthouse binary (a shell script echoing minimalLHR), and resets both
// after the test.
func setupLhTest(t *testing.T) func() {
	t.Helper()

	// Reset shared state
	lhDBMu.Lock()
	lhDB = nil
	lhDBMu.Unlock()

	// Temp dir for DB + fake binary
	tmp := t.TempDir()

	// Point the DB to an in-process temp file
	t.Setenv("LIGHTHOUSE_DB_PATH", filepath.Join(tmp, "lh_test.sqlite"))

	// Write a fake lighthouse script that just prints minimalLHR to stdout
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

// ── POST /api/lighthouse ──────────────────────────────────────────────────────

func TestPostLighthouse_scores(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	body := `{"url":"https://example.com","strategy":"mobile"}`
	req := httptest.NewRequest(http.MethodPost, "/api/lighthouse", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	PostLighthouse(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var result lighthouseResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if result.AuditID == 0 {
		t.Error("audit_id should be non-zero (record was saved)")
	}
	if result.Scores.Performance == nil || *result.Scores.Performance != 72 {
		t.Errorf("performance score: want 72, got %v", result.Scores.Performance)
	}
	if result.Scores.SEO == nil || *result.Scores.SEO != 98 {
		t.Errorf("seo score: want 98, got %v", result.Scores.SEO)
	}
	if result.Scores.Accessibility == nil || *result.Scores.Accessibility != 91 {
		t.Errorf("accessibility score: want 91, got %v", result.Scores.Accessibility)
	}
	if result.Scores.BestPractices == nil || *result.Scores.BestPractices != 83 {
		t.Errorf("best_practices score: want 83, got %v", result.Scores.BestPractices)
	}
}

func TestPostLighthouse_coreWebVitals(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	body := `{"url":"https://example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/lighthouse", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	PostLighthouse(rr, req)

	var result lighthouseResult
	json.NewDecoder(rr.Body).Decode(&result)

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

func TestPostLighthouse_failedPassedAudits(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	body := `{"url":"https://example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/lighthouse", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	PostLighthouse(rr, req)

	var result lighthouseResult
	json.NewDecoder(rr.Body).Decode(&result)

	// image-alt (score=0) and largest-contentful-paint (score=0.6) should be failed
	failedIDs := map[string]bool{}
	for _, a := range result.FailedAudits {
		failedIDs[a.ID] = true
	}
	for _, want := range []string{"image-alt", "largest-contentful-paint"} {
		if !failedIDs[want] {
			t.Errorf("expected %q in failed_audits", want)
		}
	}

	// uses-https (score=1) should be passed, and only appear once (dedup across categories)
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

// ── GET /api/lighthouse/audits ───────────────────────────────────────────────

func TestGetLighthouseAudits_empty(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	// Init DB without running any audit
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

func TestGetLighthouseAudits_afterPost(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	// Run two audits for different URLs
	for _, u := range []string{"https://example.com", "https://other.com"} {
		body := `{"url":"` + u + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/lighthouse", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		PostLighthouse(httptest.NewRecorder(), req)
	}

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
	if resp2.Audits[0].URL != "https://example.com" {
		t.Errorf("url filter: wrong url %q", resp2.Audits[0].URL)
	}
}

// ── GET /api/lighthouse/audits/{id} ─────────────────────────────────────────

func TestGetLighthouseAuditByID_roundtrip(t *testing.T) {
	cleanup := setupLhTest(t)
	defer cleanup()

	// Run one audit and capture the audit_id
	body := `{"url":"https://example.com","strategy":"desktop"}`
	postReq := httptest.NewRequest(http.MethodPost, "/api/lighthouse", strings.NewReader(body))
	postReq.Header.Set("Content-Type", "application/json")
	postRR := httptest.NewRecorder()
	PostLighthouse(postRR, postReq)

	var posted lighthouseResult
	json.NewDecoder(postRR.Body).Decode(&posted)

	if posted.AuditID == 0 {
		t.Fatal("POST returned audit_id=0")
	}

	// Retrieve by ID
	getReq := httptest.NewRequest(http.MethodGet, "/api/lighthouse/audits/"+
		itoa(posted.AuditID), nil)
	getReq = mux.SetURLVars(getReq, map[string]string{"id": itoa(posted.AuditID)})
	getRR := httptest.NewRecorder()
	GetLighthouseAuditByID(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", getRR.Code, getRR.Body.String())
	}

	var fetched lighthouseResult
	json.NewDecoder(getRR.Body).Decode(&fetched)

	if fetched.AuditID != posted.AuditID {
		t.Errorf("audit_id mismatch: want %d, got %d", posted.AuditID, fetched.AuditID)
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

	// Count occurrences of each audit ID across both lists
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

	// Verify raw DB row
	var url, strategy string
	var sp, ss sql.NullInt64
	err := lhDB.QueryRow(
		`SELECT url, strategy, score_performance, score_seo FROM lighthouse_audits WHERE id = ?`, id,
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
