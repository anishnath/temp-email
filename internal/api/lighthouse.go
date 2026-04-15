package api

import (
	"context"
	"database/sql"
	"encoding/json"
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
  passed_audits        TEXT
);
CREATE INDEX IF NOT EXISTS lh_url ON lighthouse_audits(url);
CREATE INDEX IF NOT EXISTS lh_fetched ON lighthouse_audits(fetched_at DESC);
`

func lhDBPath() string {
	if v := os.Getenv("LIGHTHOUSE_DB_PATH"); v != "" {
		return v
	}
	return "data/lighthouse.sqlite"
}

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
	lhDB = db
	return nil
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

type lighthouseAudit struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Description  string   `json:"description,omitempty"`
	Score        *float64 `json:"score"`
	DisplayValue string   `json:"display_value,omitempty"`
}

// lighthouseResult is returned by POST and GET /audits/{id}.
type lighthouseResult struct {
	AuditID       int64             `json:"audit_id"`
	URL           string            `json:"url"`
	Strategy      string            `json:"strategy"`
	Categories    []string          `json:"categories"`
	FetchedAt     string            `json:"fetched_at"`
	Scores        lighthouseScores  `json:"scores"`
	CoreWebVitals map[string]string `json:"core_web_vitals,omitempty"`
	FailedAudits  []lighthouseAudit `json:"failed_audits"`
	PassedAudits  []lighthouseAudit `json:"passed_audits"`
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
		ID               string   `json:"id"`
		Title            string   `json:"title"`
		Description      string   `json:"description"`
		Score            *float64 `json:"score"`
		ScoreDisplayMode string   `json:"scoreDisplayMode"`
		DisplayValue     string   `json:"displayValue"`
	} `json:"audits"`
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

// PostLighthouse runs Lighthouse, stores the result in SQLite, and returns it
// with an audit_id for later retrieval.
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

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(lhTimeoutSec())*time.Second)
	defer cancel()

	// lighthouse is invoked via exec (no shell), so chrome flags must be passed
	// as a single --chrome-flags argument with the value quoted as one token.
	// Split into individual per-flag arguments so lighthouse can reassemble them.
	chromeFlags := strings.Fields(lhChromeFlags())
	chromeFlagArgs := make([]string, 0, len(chromeFlags))
	for _, f := range chromeFlags {
		chromeFlagArgs = append(chromeFlagArgs, "--chrome-flags="+f)
	}

	args := []string{
		req.URL,
		"--output", "json",
		"--output-path", "stdout",
		"--quiet",
		"--only-categories=" + strings.Join(cats, ","),
		"--form-factor=" + strategy,
	}
	args = append(args, chromeFlagArgs...)

	log.Printf("lighthouse cmd: %s %v", lhCmd(), args)
	cmd := exec.CommandContext(ctx, lhCmd(), args...)
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			http.Error(w, "lighthouse timed out", http.StatusGatewayTimeout)
			return
		}
		log.Printf("lighthouse exec error: %v\nstderr: %s", err, stderrBuf.String())
		http.Error(w, "lighthouse failed: "+err.Error()+"\n"+stderrBuf.String(), http.StatusInternalServerError)
		return
	}
	if stderrBuf.Len() > 0 {
		log.Printf("lighthouse stderr: %s", stderrBuf.String())
	}

	var lhr lhJSON
	if err := json.Unmarshal(out, &lhr); err != nil {
		log.Printf("lighthouse json parse: %v", err)
		http.Error(w, "failed to parse lighthouse output", http.StatusInternalServerError)
		return
	}

	result := buildLighthouseResult(req.URL, strategy, cats, lhr)
	result.AuditID = saveLighthouseResult(result)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// GetLighthouseAudits lists recent audits, optionally filtered by URL.
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

	var result lighthouseResult
	var catsStr, cwvJSON, failedJSON, passedJSON sql.NullString
	var sp, sa, sbp, ss sql.NullInt64

	err = lhDB.QueryRow(`
		SELECT id, url, strategy, categories, fetched_at,
		       score_performance, score_accessibility, score_best_practices, score_seo,
		       core_web_vitals, failed_audits, passed_audits
		FROM lighthouse_audits WHERE id = ?`, id).Scan(
		&result.AuditID, &result.URL, &result.Strategy, &catsStr, &result.FetchedAt,
		&sp, &sa, &sbp, &ss,
		&cwvJSON, &failedJSON, &passedJSON,
	)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("lighthouse get: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	result.Categories = splitCats(catsStr.String)
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
	if result.FailedAudits == nil {
		result.FailedAudits = []lighthouseAudit{}
	}
	if result.PassedAudits == nil {
		result.PassedAudits = []lighthouseAudit{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
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
			item := lighthouseAudit{
				ID:           a.ID,
				Title:        a.Title,
				Description:  a.Description,
				Score:        a.Score,
				DisplayValue: a.DisplayValue,
			}
			if a.Score == nil || *a.Score < 0.9 {
				result.FailedAudits = append(result.FailedAudits, item)
			} else {
				result.PassedAudits = append(result.PassedAudits, item)
			}
		}
	}
	return result
}

func saveLighthouseResult(r lighthouseResult) int64 {
	cwvJSON, _ := json.Marshal(r.CoreWebVitals)
	failedJSON, _ := json.Marshal(r.FailedAudits)
	passedJSON, _ := json.Marshal(r.PassedAudits)

	res, err := lhDB.Exec(`
		INSERT INTO lighthouse_audits
		  (url, strategy, categories, fetched_at,
		   score_performance, score_accessibility, score_best_practices, score_seo,
		   core_web_vitals, failed_audits, passed_audits)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.URL, r.Strategy, strings.Join(r.Categories, ","), r.FetchedAt,
		r.Scores.Performance, r.Scores.Accessibility, r.Scores.BestPractices, r.Scores.SEO,
		string(cwvJSON), string(failedJSON), string(passedJSON),
	)
	if err != nil {
		log.Printf("lighthouse save: %v", err)
		return 0
	}
	id, _ := res.LastInsertId()
	return id
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
