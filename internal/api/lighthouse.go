package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

// ── DB init ──────────────────────────────────────────────────────────────────

var (
	lhDBMu sync.Mutex
	lhDB   *sql.DB
)

const lhSchema = `
CREATE TABLE IF NOT EXISTS lighthouse_audits (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  url                  TEXT NOT NULL,
  strategy             TEXT NOT NULL DEFAULT 'mobile',
  categories           TEXT NOT NULL DEFAULT '',
  fetched_at           TEXT NOT NULL DEFAULT (datetime('now')),
  score_performance    INTEGER,
  score_accessibility  INTEGER,
  score_best_practices INTEGER,
  score_seo            INTEGER,
  core_web_vitals      TEXT,
  failed_audits        TEXT,
  passed_audits        TEXT,
  screenshot           TEXT,
  thumbnails           TEXT
);
CREATE INDEX IF NOT EXISTS lh_url     ON lighthouse_audits(url);
CREATE INDEX IF NOT EXISTS lh_fetched ON lighthouse_audits(fetched_at DESC);

CREATE TABLE IF NOT EXISTS lighthouse_jobs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  status      TEXT NOT NULL DEFAULT 'queued',
  url         TEXT NOT NULL,
  strategy    TEXT NOT NULL DEFAULT 'mobile',
  categories  TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  started_at  TEXT,
  finished_at TEXT,
  audit_id    INTEGER,
  error       TEXT
);
CREATE INDEX IF NOT EXISTS lhj_status  ON lighthouse_jobs(status);
CREATE INDEX IF NOT EXISTS lhj_created ON lighthouse_jobs(created_at DESC);
`

func lhDBPath() string {
	if v := os.Getenv("LIGHTHOUSE_DB_PATH"); v != "" {
		return v
	}
	return "data/lighthouse.sqlite"
}

// lhWorkerStarted is protected by lhWorkerMu.
// Using a plain bool (not sync.Once) so tests can reset it.
var (
	lhWorkerMu      sync.Mutex
	lhWorkerStarted bool
)

func initLhDB() error {
	lhDBMu.Lock()
	defer lhDBMu.Unlock()
	if lhDB != nil {
		return nil
	}
	path := lhDBPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	db, err := sql.Open("sqlite3", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(lhSchema); err != nil {
		return err
	}
	// Migrate: add columns added after initial schema (safe to run on existing DBs).
	for _, col := range []string{
		"ALTER TABLE lighthouse_audits ADD COLUMN screenshot TEXT",
		"ALTER TABLE lighthouse_audits ADD COLUMN thumbnails TEXT",
	} {
		db.Exec(col) // ignore "duplicate column" errors on existing DBs
	}
	lhDB = db
	startLighthouseWorkers()
	return nil
}

func startLighthouseWorkers() {
	lhWorkerMu.Lock()
	defer lhWorkerMu.Unlock()
	if lhWorkerStarted {
		return
	}
	lhJobQueue = make(chan int64, lhQueueSize())
	n := lhWorkerCount()
	log.Printf("lighthouse: starting %d worker(s), queue size %d", n, lhQueueSize())
	for i := 0; i < n; i++ {
		go lighthouseWorker()
	}
	lhWorkerStarted = true
}

// ── Queue / worker ────────────────────────────────────────────────────────────

var lhJobQueue chan int64

func lhWorkerCount() int {
	if v := os.Getenv("LIGHTHOUSE_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 10 {
			return n
		}
	}
	return 2
}

func lhQueueSize() int {
	if v := os.Getenv("LIGHTHOUSE_QUEUE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			return n
		}
	}
	return 100
}

func lighthouseWorker() {
	for jobID := range lhJobQueue {
		processLighthouseJob(jobID)
	}
}

func processLighthouseJob(jobID int64) {
	// Safely read the current DB reference; bail if DB was reset (e.g. in tests).
	lhDBMu.Lock()
	db := lhDB
	lhDBMu.Unlock()
	if db == nil {
		log.Printf("lighthouse worker: db is nil, skipping job %d", jobID)
		return
	}

	// Mark running.
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = db.Exec(
		`UPDATE lighthouse_jobs SET status='running', started_at=? WHERE id=?`,
		now, jobID,
	)

	// Read job details.
	var url, strategy, catsStr string
	err := db.QueryRow(
		`SELECT url, strategy, categories FROM lighthouse_jobs WHERE id=?`, jobID,
	).Scan(&url, &strategy, &catsStr)
	if err != nil {
		lhJobFailDB(db, jobID, "could not read job: "+err.Error())
		return
	}
	cats := splitCats(catsStr)

	// Build and run lighthouse.
	result, err := runLighthouse(url, strategy, cats)
	if err != nil {
		lhJobFailDB(db, jobID, err.Error())
		return
	}

	// Save audit and link to job.
	auditID := saveLighthouseResultDB(db, result)
	done := time.Now().UTC().Format(time.RFC3339)
	_, _ = db.Exec(
		`UPDATE lighthouse_jobs SET status='done', finished_at=?, audit_id=? WHERE id=?`,
		done, auditID, jobID,
	)
	log.Printf("lighthouse job %d done → audit %d", jobID, auditID)
}

func lhJobFailDB(db *sql.DB, jobID int64, msg string) {
	done := time.Now().UTC().Format(time.RFC3339)
	_, _ = db.Exec(
		`UPDATE lighthouse_jobs SET status='failed', finished_at=?, error=? WHERE id=?`,
		done, msg, jobID,
	)
	log.Printf("lighthouse job %d failed: %s", jobID, msg)
}

// ── Types ─────────────────────────────────────────────────────────────────────

type lighthouseRequest struct {
	URL        string   `json:"url"`
	Strategy   string   `json:"strategy"`   // "mobile" (default) | "desktop"
	Categories []string `json:"categories"` // default: all four
}

type lighthouseScores struct {
	Performance   *int `json:"performance,omitempty"`
	Accessibility *int `json:"accessibility,omitempty"`
	BestPractices *int `json:"best_practices,omitempty"`
	SEO           *int `json:"seo,omitempty"`
}

// auditDetails holds the evidence items from a Lighthouse audit.
// Items are kept as raw JSON because their shape varies per audit type.
type auditDetails struct {
	Type                string            `json:"type,omitempty"`
	Items               []json.RawMessage `json:"items,omitempty"`
	OverallSavingsMs    float64           `json:"overall_savings_ms,omitempty"`
	OverallSavingsBytes int64             `json:"overall_savings_bytes,omitempty"`
}

type lighthouseAudit struct {
	ID           string        `json:"id"`
	Title        string        `json:"title"`
	Description  string        `json:"description,omitempty"`
	Score        *float64      `json:"score"`
	DisplayValue string        `json:"display_value,omitempty"`
	Details      *auditDetails `json:"details,omitempty"`
}

// lighthouseScreenshot holds the page screenshot captured by Lighthouse.
// Data is a data URL: "data:image/jpeg;base64,..."
type lighthouseScreenshot struct {
	Data   string `json:"data"` // base64 data URL
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
}

// lighthouseThumbnail is one frame from the page-load filmstrip.
type lighthouseThumbnail struct {
	Timestamp float64 `json:"timestamp"` // ms from start
	Data      string  `json:"data"`      // base64 data URL
}

// lighthouseResult is the full audit result (stored in SQLite and returned by GET /audits/{id}).
type lighthouseResult struct {
	AuditID       int64                 `json:"audit_id"`
	URL           string                `json:"url"`
	Strategy      string                `json:"strategy"`
	Categories    []string              `json:"categories"`
	FetchedAt     string                `json:"fetched_at"`
	Scores        lighthouseScores      `json:"scores"`
	CoreWebVitals map[string]string     `json:"core_web_vitals,omitempty"`
	Screenshot    *lighthouseScreenshot `json:"screenshot,omitempty"`
	Thumbnails    []lighthouseThumbnail `json:"thumbnails,omitempty"`
	FailedAudits  []lighthouseAudit     `json:"failed_audits"`
	PassedAudits  []lighthouseAudit     `json:"passed_audits"`
}

// lighthouseJobResponse is returned immediately by POST /api/lighthouse.
type lighthouseJobResponse struct {
	JobID      int64    `json:"job_id"`
	Status     string   `json:"status"`
	URL        string   `json:"url"`
	Strategy   string   `json:"strategy"`
	Categories []string `json:"categories"`
	CreatedAt  string   `json:"created_at"`
	QueueDepth int      `json:"queue_depth"`
}

// lighthouseJobStatus is returned by GET /api/lighthouse/jobs/{id}.
type lighthouseJobStatus struct {
	JobID      int64             `json:"job_id"`
	Status     string            `json:"status"` // queued | running | done | failed
	URL        string            `json:"url"`
	Strategy   string            `json:"strategy"`
	Categories []string          `json:"categories"`
	CreatedAt  string            `json:"created_at"`
	StartedAt  string            `json:"started_at,omitempty"`
	FinishedAt string            `json:"finished_at,omitempty"`
	Error      string            `json:"error,omitempty"`
	Result     *lighthouseResult `json:"result,omitempty"` // populated when status == "done"
}

// lighthouseListItem is the lightweight row used in GET /api/lighthouse/audits.
type lighthouseListItem struct {
	AuditID    int64            `json:"audit_id"`
	URL        string           `json:"url"`
	Strategy   string           `json:"strategy"`
	Categories []string         `json:"categories"`
	FetchedAt  string           `json:"fetched_at"`
	Scores     lighthouseScores `json:"scores"`
}

// lhJSON mirrors the minimal subset of the Lighthouse result JSON we need.
type lhJSON struct {
	Categories map[string]struct {
		Score     *float64 `json:"score"`
		AuditRefs []struct {
			ID string `json:"id"`
		} `json:"auditRefs"`
	} `json:"categories"`
	Audits map[string]struct {
		ID               string          `json:"id"`
		Title            string          `json:"title"`
		Description      string          `json:"description"`
		Score            *float64        `json:"score"`
		ScoreDisplayMode string          `json:"scoreDisplayMode"`
		DisplayValue     string          `json:"displayValue"`
		Details          json.RawMessage `json:"details"`
	} `json:"audits"`
}

// lhScreenshotDetails matches the details block of the final-screenshot audit.
type lhScreenshotDetails struct {
	Type   string `json:"type"`
	Data   string `json:"data"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

// lhThumbnailDetails matches the details block of the screenshot-thumbnails audit.
type lhThumbnailDetails struct {
	Type  string `json:"type"`
	Items []struct {
		Timestamp float64 `json:"timestamp"`
		Data      string  `json:"data"`
	} `json:"items"`
}

// lhRawDetails is used to partially unmarshal an audit's details block.
type lhRawDetails struct {
	Type                string            `json:"type"`
	Items               []json.RawMessage `json:"items"`
	OverallSavingsMs    float64           `json:"overallSavingsMs"`
	OverallSavingsBytes int64             `json:"overallSavingsBytes"`
}

// auditIDsWithNoUsefulItems are audits whose details.items are either binary,
// extremely large, or not actionable evidence (screenshots, raw traces, etc.).
var auditIDsWithNoUsefulItems = map[string]bool{
	"screenshot-thumbnails": true,
	"final-screenshot":      true,
	"network-requests":      true,
	"main-thread-tasks":     true,
	"metrics":               true,
	"script-treemap-data":   true,
	"resource-summary":      true,
	"diagnostics":           true,
	"long-tasks":            true,
}

// ── Config helpers ────────────────────────────────────────────────────────────

func lhCmd() string {
	if v := os.Getenv("LIGHTHOUSE_CMD"); v != "" {
		return v
	}
	return "lighthouse"
}

func lhChromeFlags() string {
	if v := os.Getenv("LIGHTHOUSE_CHROME_FLAGS"); v != "" {
		return v
	}
	return "--headless --no-sandbox --disable-gpu --disable-dev-shm-usage"
}

func lhTimeoutSec() int {
	if v := os.Getenv("LIGHTHOUSE_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 120
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// PostLighthouse enqueues an async Lighthouse audit job and returns immediately.
//
// POST /api/lighthouse
func PostLighthouse(w http.ResponseWriter, r *http.Request) {
	if err := initLhDB(); err != nil {
		http.Error(w, "lighthouse db: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var req lighthouseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		http.Error(w, "url is required", http.StatusBadRequest)
		return
	}

	strategy := "mobile"
	if req.Strategy == "desktop" {
		strategy = "desktop"
	}
	cats := req.Categories
	if len(cats) == 0 {
		cats = []string{"performance", "seo", "accessibility", "best-practices"}
	}

	// Reject if queue is full to protect the server.
	if len(lhJobQueue) >= cap(lhJobQueue) {
		http.Error(w, "queue full, try again later", http.StatusTooManyRequests)
		return
	}

	createdAt := time.Now().UTC().Format(time.RFC3339)
	res, err := lhDB.Exec(
		`INSERT INTO lighthouse_jobs (status, url, strategy, categories, created_at)
		 VALUES ('queued', ?, ?, ?, ?)`,
		req.URL, strategy, strings.Join(cats, ","), createdAt,
	)
	if err != nil {
		log.Printf("lighthouse enqueue: %v", err)
		http.Error(w, "failed to create job", http.StatusInternalServerError)
		return
	}
	jobID, _ := res.LastInsertId()

	// Non-blocking send — we already checked capacity above.
	lhJobQueue <- jobID

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(lighthouseJobResponse{
		JobID:      jobID,
		Status:     "queued",
		URL:        req.URL,
		Strategy:   strategy,
		Categories: cats,
		CreatedAt:  createdAt,
		QueueDepth: len(lhJobQueue),
	})
}

// GetLighthouseJob returns the status (and result when done) for a job.
//
// GET /api/lighthouse/jobs/{id}
func GetLighthouseJob(w http.ResponseWriter, r *http.Request) {
	if err := initLhDB(); err != nil {
		http.Error(w, "lighthouse db: "+err.Error(), http.StatusInternalServerError)
		return
	}

	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	var job lighthouseJobStatus
	var catsStr string
	var startedAt, finishedAt, jobError sql.NullString
	var auditID sql.NullInt64

	err = lhDB.QueryRow(`
		SELECT id, status, url, strategy, categories,
		       created_at, started_at, finished_at, audit_id, error
		FROM lighthouse_jobs WHERE id=?`, id).Scan(
		&job.JobID, &job.Status, &job.URL, &job.Strategy, &catsStr,
		&job.CreatedAt, &startedAt, &finishedAt, &auditID, &jobError,
	)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("lighthouse job get: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	job.Categories = splitCats(catsStr)
	job.StartedAt = startedAt.String
	job.FinishedAt = finishedAt.String
	job.Error = jobError.String

	// Attach full result when the job completed successfully.
	if job.Status == "done" && auditID.Valid {
		result := lhLoadAudit(auditID.Int64)
		job.Result = result
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(job)
}

// GetLighthouseAudits lists completed audits, optionally filtered by URL.
//
// GET /api/lighthouse/audits?url=https://example.com&limit=20
func GetLighthouseAudits(w http.ResponseWriter, r *http.Request) {
	if err := initLhDB(); err != nil {
		http.Error(w, "lighthouse db: "+err.Error(), http.StatusInternalServerError)
		return
	}

	urlFilter := r.URL.Query().Get("url")
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	where := ""
	args := []interface{}{}
	if urlFilter != "" {
		where = "WHERE url = ?"
		args = append(args, urlFilter)
	}
	args = append(args, limit)

	rows, err := lhDB.Query(`
		SELECT id, url, strategy, categories, fetched_at,
		       score_performance, score_accessibility, score_best_practices, score_seo
		FROM lighthouse_audits
		`+where+`
		ORDER BY fetched_at DESC
		LIMIT ?`, args...)
	if err != nil {
		log.Printf("lighthouse list: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var items []lighthouseListItem
	for rows.Next() {
		var it lighthouseListItem
		var catsStr string
		var sp, sa, sbp, ss sql.NullInt64
		if err := rows.Scan(&it.AuditID, &it.URL, &it.Strategy, &catsStr, &it.FetchedAt,
			&sp, &sa, &sbp, &ss); err != nil {
			log.Printf("lighthouse list scan: %v", err)
			continue
		}
		it.Categories = splitCats(catsStr)
		it.Scores = nullIntsToScores(sp, sa, sbp, ss)
		items = append(items, it)
	}
	if items == nil {
		items = []lighthouseListItem{}
	}

	type listResp struct {
		Count  int                  `json:"count"`
		Audits []lighthouseListItem `json:"audits"`
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listResp{Count: len(items), Audits: items})
}

// GetLighthouseAuditByID returns the full stored result for one audit.
//
// GET /api/lighthouse/audits/{id}
func GetLighthouseAuditByID(w http.ResponseWriter, r *http.Request) {
	if err := initLhDB(); err != nil {
		http.Error(w, "lighthouse db: "+err.Error(), http.StatusInternalServerError)
		return
	}

	id, err := strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	result := lhLoadAudit(id)
	if result == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// ── Core lighthouse runner ─────────────────────────────────────────────────────

func runLighthouse(url, strategy string, cats []string) (lighthouseResult, error) {
	chromeFlags := strings.Fields(lhChromeFlags())
	chromeFlagArgs := make([]string, 0, len(chromeFlags))
	for _, f := range chromeFlags {
		chromeFlagArgs = append(chromeFlagArgs, "--chrome-flags="+f)
	}

	args := []string{
		url,
		"--output", "json",
		"--output-path", "stdout",
		"--quiet",
		"--only-categories=" + strings.Join(cats, ","),
		"--form-factor=" + strategy,
	}
	args = append(args, chromeFlagArgs...)

	log.Printf("lighthouse cmd: %s %v", lhCmd(), args)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(lhTimeoutSec())*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, lhCmd(), args...)
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return lighthouseResult{}, fmt.Errorf("lighthouse timed out after %ds", lhTimeoutSec())
		}
		stderr := stderrBuf.String()
		log.Printf("lighthouse exec error: %v\nstderr: %s", err, stderr)
		return lighthouseResult{}, fmt.Errorf("%v: %s", err, stderr)
	}
	if stderrBuf.Len() > 0 {
		log.Printf("lighthouse stderr: %s", stderrBuf.String())
	}

	var lhr lhJSON
	if err := json.Unmarshal(out, &lhr); err != nil {
		log.Printf("lighthouse json parse: %v", err)
		return lighthouseResult{}, fmt.Errorf("failed to parse lighthouse output: %v", err)
	}

	return buildLighthouseResult(url, strategy, cats, lhr), nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func buildLighthouseResult(url, strategy string, cats []string, lhr lhJSON) lighthouseResult {
	scoreInt := func(s *float64) *int {
		if s == nil {
			return nil
		}
		v := int(math.Round(*s * 100))
		return &v
	}

	result := lighthouseResult{
		URL:          url,
		Strategy:     strategy,
		Categories:   cats,
		FetchedAt:    time.Now().UTC().Format(time.RFC3339),
		FailedAudits: []lighthouseAudit{},
		PassedAudits: []lighthouseAudit{},
	}

	if c, ok := lhr.Categories["performance"]; ok {
		result.Scores.Performance = scoreInt(c.Score)
	}
	if c, ok := lhr.Categories["accessibility"]; ok {
		result.Scores.Accessibility = scoreInt(c.Score)
	}
	if c, ok := lhr.Categories["best-practices"]; ok {
		result.Scores.BestPractices = scoreInt(c.Score)
	}
	if c, ok := lhr.Categories["seo"]; ok {
		result.Scores.SEO = scoreInt(c.Score)
	}

	cwvIDs := map[string]string{
		"first-contentful-paint":   "FCP",
		"largest-contentful-paint": "LCP",
		"total-blocking-time":      "TBT",
		"cumulative-layout-shift":  "CLS",
		"speed-index":              "Speed Index",
		"interactive":              "TTI",
		"server-response-time":     "TTFB",
	}
	cwv := map[string]string{}
	for auditID, label := range cwvIDs {
		if a, ok := lhr.Audits[auditID]; ok && a.DisplayValue != "" {
			cwv[label] = a.DisplayValue
		}
	}
	if len(cwv) > 0 {
		result.CoreWebVitals = cwv
	}

	// Extract final screenshot.
	if ss, ok := lhr.Audits["final-screenshot"]; ok && len(ss.Details) > 0 {
		var d lhScreenshotDetails
		if err := json.Unmarshal(ss.Details, &d); err == nil && d.Data != "" {
			result.Screenshot = &lighthouseScreenshot{
				Data:   d.Data,
				Width:  d.Width,
				Height: d.Height,
			}
		}
	}

	// Extract filmstrip thumbnails.
	if th, ok := lhr.Audits["screenshot-thumbnails"]; ok && len(th.Details) > 0 {
		var d lhThumbnailDetails
		if err := json.Unmarshal(th.Details, &d); err == nil {
			for _, item := range d.Items {
				if item.Data != "" {
					result.Thumbnails = append(result.Thumbnails, lighthouseThumbnail{
						Timestamp: item.Timestamp,
						Data:      item.Data,
					})
				}
			}
		}
	}

	seen := map[string]bool{}
	for _, catKey := range []string{"performance", "accessibility", "best-practices", "seo"} {
		cat, ok := lhr.Categories[catKey]
		if !ok {
			continue
		}
		for _, ref := range cat.AuditRefs {
			a, ok := lhr.Audits[ref.ID]
			if !ok || seen[ref.ID] {
				continue
			}
			seen[ref.ID] = true
			mode := a.ScoreDisplayMode
			if mode == "informational" || mode == "not-applicable" || mode == "manual" {
				continue
			}
			isFailed := a.Score == nil || *a.Score < 0.9
			item := lighthouseAudit{
				ID:           a.ID,
				Title:        a.Title,
				Description:  a.Description,
				Score:        a.Score,
				DisplayValue: a.DisplayValue,
			}
			if isFailed && len(a.Details) > 0 && !auditIDsWithNoUsefulItems[a.ID] {
				var raw lhRawDetails
				if err := json.Unmarshal(a.Details, &raw); err == nil && len(raw.Items) > 0 {
					item.Details = &auditDetails{
						Type:                raw.Type,
						Items:               raw.Items,
						OverallSavingsMs:    raw.OverallSavingsMs,
						OverallSavingsBytes: raw.OverallSavingsBytes,
					}
				}
			}
			if isFailed {
				result.FailedAudits = append(result.FailedAudits, item)
			} else {
				result.PassedAudits = append(result.PassedAudits, item)
			}
		}
	}
	return result
}

func saveLighthouseResult(r lighthouseResult) int64 {
	return saveLighthouseResultDB(lhDB, r)
}

func saveLighthouseResultDB(db *sql.DB, r lighthouseResult) int64 {
	cwvJSON, _ := json.Marshal(r.CoreWebVitals)
	failedJSON, _ := json.Marshal(r.FailedAudits)
	passedJSON, _ := json.Marshal(r.PassedAudits)
	screenshotJSON, _ := json.Marshal(r.Screenshot)
	thumbnailsJSON, _ := json.Marshal(r.Thumbnails)

	res, err := db.Exec(`
		INSERT INTO lighthouse_audits
		  (url, strategy, categories, fetched_at,
		   score_performance, score_accessibility, score_best_practices, score_seo,
		   core_web_vitals, failed_audits, passed_audits, screenshot, thumbnails)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.URL, r.Strategy, strings.Join(r.Categories, ","), r.FetchedAt,
		r.Scores.Performance, r.Scores.Accessibility, r.Scores.BestPractices, r.Scores.SEO,
		string(cwvJSON), string(failedJSON), string(passedJSON),
		string(screenshotJSON), string(thumbnailsJSON),
	)
	if err != nil {
		log.Printf("lighthouse save: %v", err)
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

// lhLoadAudit reads a full lighthouseResult from the DB by audit ID.
// Returns nil if not found.
func lhLoadAudit(id int64) *lighthouseResult {
	var result lighthouseResult
	var catsStr string
	var cwvJSON, failedJSON, passedJSON, screenshotJSON, thumbnailsJSON sql.NullString
	var sp, sa, sbp, ss sql.NullInt64

	err := lhDB.QueryRow(`
		SELECT id, url, strategy, categories, fetched_at,
		       score_performance, score_accessibility, score_best_practices, score_seo,
		       core_web_vitals, failed_audits, passed_audits, screenshot, thumbnails
		FROM lighthouse_audits WHERE id=?`, id).Scan(
		&result.AuditID, &result.URL, &result.Strategy, &catsStr, &result.FetchedAt,
		&sp, &sa, &sbp, &ss,
		&cwvJSON, &failedJSON, &passedJSON, &screenshotJSON, &thumbnailsJSON,
	)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		log.Printf("lighthouse load audit: %v", err)
		return nil
	}

	result.Categories = splitCats(catsStr)
	result.Scores = nullIntsToScores(sp, sa, sbp, ss)

	if cwvJSON.Valid && cwvJSON.String != "" {
		_ = json.Unmarshal([]byte(cwvJSON.String), &result.CoreWebVitals)
	}
	if failedJSON.Valid && failedJSON.String != "" {
		_ = json.Unmarshal([]byte(failedJSON.String), &result.FailedAudits)
	}
	if passedJSON.Valid && passedJSON.String != "" {
		_ = json.Unmarshal([]byte(passedJSON.String), &result.PassedAudits)
	}
	if screenshotJSON.Valid && screenshotJSON.String != "" && screenshotJSON.String != "null" {
		var sc lighthouseScreenshot
		if json.Unmarshal([]byte(screenshotJSON.String), &sc) == nil && sc.Data != "" {
			result.Screenshot = &sc
		}
	}
	if thumbnailsJSON.Valid && thumbnailsJSON.String != "" && thumbnailsJSON.String != "null" {
		_ = json.Unmarshal([]byte(thumbnailsJSON.String), &result.Thumbnails)
	}
	if result.FailedAudits == nil {
		result.FailedAudits = []lighthouseAudit{}
	}
	if result.PassedAudits == nil {
		result.PassedAudits = []lighthouseAudit{}
	}
	return &result
}

func splitCats(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ",")
}

func nullIntsToScores(sp, sa, sbp, ss sql.NullInt64) lighthouseScores {
	nullToPtr := func(n sql.NullInt64) *int {
		if !n.Valid {
			return nil
		}
		v := int(n.Int64)
		return &v
	}
	return lighthouseScores{
		Performance:   nullToPtr(sp),
		Accessibility: nullToPtr(sa),
		BestPractices: nullToPtr(sbp),
		SEO:           nullToPtr(ss),
	}
}
