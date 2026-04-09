package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/gorilla/mux"

	"temp-email/internal/seocrawl"
	"temp-email/internal/seocrawl/config"
	"temp-email/internal/seocrawl/models"
	"temp-email/internal/seocrawl/services"
	"temp-email/internal/seocrawl/store"
)

type seoCrawlRequest struct {
	URL                string `json:"url"`
	IgnoreRobotsTxt    bool   `json:"ignore_robots_txt"`
	FollowNofollow     bool   `json:"follow_nofollow"`
	IncludeNoindex     bool   `json:"include_noindex"`
	CrawlSitemap       bool   `json:"crawl_sitemap"`
	AllowSubdomains    bool   `json:"allow_subdomains"`
	CheckExternalLinks bool   `json:"check_external_links"`
	UserAgent          string `json:"user_agent"`
}

type seoCrawlStartResponse struct {
	CrawlID   int64 `json:"crawl_id"`
	ProjectID int64 `json:"project_id"`
}

type seoCrawlStatusResponse struct {
	CrawlID         int64 `json:"crawl_id"`
	ProjectID       int64 `json:"project_id"`
	Crawling        bool  `json:"crawling"`
	TotalURLs       int   `json:"total_urls"`
	TotalIssues     int   `json:"total_issues"`
	CriticalIssues  int   `json:"critical_issues"`
	AlertIssues     int   `json:"alert_issues"`
	WarningIssues   int   `json:"warning_issues"`
	RobotstxtExists bool  `json:"robotstxt_exists"`
	SitemapExists   bool  `json:"sitemap_exists"`
}

var (
	seoMu     sync.Mutex
	seoDB     *sql.DB
	seoCrawl  *services.CrawlerService
	seoCrawlR *store.CrawlRepository
	seoIssueR *store.IssueRepository
	seoPageR  *store.PageReportRepository
)

func seoPath() string {
	p := os.Getenv("SEO_DB_PATH")
	if p == "" {
		return "data/seo.sqlite"
	}
	return p
}

func initSEO() error {
	seoMu.Lock()
	defer seoMu.Unlock()
	if seoDB != nil {
		return nil
	}
	path := seoPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	cfg := config.LoadCrawlerFromEnv()
	db, err := seocrawl.OpenSQLite(path, cfg.DBMaxOpenConns)
	if err != nil {
		return err
	}
	seoDB = db
	seoCrawl = seocrawl.NewCrawlerService(db, cfg)
	seoCrawlR = &store.CrawlRepository{DB: db}
	seoIssueR = &store.IssueRepository{DB: db}
	seoPageR = &store.PageReportRepository{DB: db}
	return nil
}

// GetSEOCrawlList returns a list of recent crawls, optionally filtered by seed URL.
// GET /api/seo/crawls?url=https://example.com&limit=20
func GetSEOCrawlList(w http.ResponseWriter, r *http.Request) {
	if err := initSEO(); err != nil {
		http.Error(w, "seo database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	urlFilter := r.URL.Query().Get("url")
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := seoCrawlR.ListCrawls(urlFilter, limit)
	if err != nil {
		log.Printf("seo ListCrawls: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []store.CrawlListRow{}
	}
	type listResp struct {
		Count  int                  `json:"count"`
		Crawls []store.CrawlListRow `json:"crawls"`
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listResp{Count: len(rows), Crawls: rows})
}

// PostSEOCancelCrawl signals a running crawl to stop early.
// POST /api/seo/crawl/{id}/cancel
func PostSEOCancelCrawl(w http.ResponseWriter, r *http.Request) {
	if err := initSEO(); err != nil {
		http.Error(w, "seo database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	crawlID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil || crawlID < 1 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var projectID int64
	if err := seoDB.QueryRow(`SELECT project_id FROM crawls WHERE id = ?`, crawlID).Scan(&projectID); err != nil {
		http.Error(w, "crawl not found", http.StatusNotFound)
		return
	}
	stopped := seoCrawl.StopCrawlerByProjectID(projectID)
	type cancelResp struct {
		CrawlID int64  `json:"crawl_id"`
		Stopped bool   `json:"stopped"`
		Message string `json:"message"`
	}
	msg := "crawl stopped"
	if !stopped {
		msg = "crawl was not running (already finished or not found)"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cancelResp{CrawlID: crawlID, Stopped: stopped, Message: msg})
}

// PostSEOStartCrawl starts a full-site SEO audit (SEOnaut-equivalent) in the background.
func PostSEOStartCrawl(w http.ResponseWriter, r *http.Request) {
	if err := initSEO(); err != nil {
		http.Error(w, "seo database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var req seoCrawlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		http.Error(w, "url is required", http.StatusBadRequest)
		return
	}
	p := models.Project{
		URL:                req.URL,
		IgnoreRobotsTxt:    req.IgnoreRobotsTxt,
		FollowNofollow:     req.FollowNofollow,
		IncludeNoindex:     req.IncludeNoindex,
		CrawlSitemap:       req.CrawlSitemap,
		AllowSubdomains:    req.AllowSubdomains,
		CheckExternalLinks: req.CheckExternalLinks,
		UserAgent:          req.UserAgent,
	}
	if err := seoCrawlR.InsertProject(&p); err != nil {
		log.Printf("seo InsertProject: %v", err)
		http.Error(w, "failed to create project", http.StatusInternalServerError)
		return
	}
	crawl, err := seoCrawl.StartCrawler(p, models.BasicAuth{})
	if err != nil {
		log.Printf("seo StartCrawler: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(seoCrawlStartResponse{CrawlID: crawl.Id, ProjectID: p.Id})
}

// GetSEOStatus returns crawl progress and issue counts.
func GetSEOStatus(w http.ResponseWriter, r *http.Request) {
	if err := initSEO(); err != nil {
		http.Error(w, "seo database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	id, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	c, err := seoCrawlR.GetCrawlByID(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var pid int64
	if err := seoDB.QueryRow(`SELECT project_id FROM crawls WHERE id = ?`, id).Scan(&pid); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(seoCrawlStatusResponse{
		CrawlID:         c.Id,
		ProjectID:       pid,
		Crawling:        c.Crawling,
		TotalURLs:       c.TotalURLs,
		TotalIssues:     c.TotalIssues,
		CriticalIssues:  c.CriticalIssues,
		AlertIssues:     c.AlertIssues,
		WarningIssues:   c.WarningIssues,
		RobotstxtExists: c.RobotstxtExists,
		SitemapExists:   c.SitemapExists,
	})
}

type seoFindingsResponse struct {
	CrawlID   int64               `json:"crawl_id"`
	ProjectID int64               `json:"project_id"`
	Critical  []models.IssueGroup `json:"critical"`
	Alert     []models.IssueGroup `json:"alert"`
	Warning   []models.IssueGroup `json:"warning"`
	Note      string              `json:"note"`
}

// GetSEOFindings returns issue types and page counts per severity (same data SEOnaut dashboard uses).
func GetSEOFindings(w http.ResponseWriter, r *http.Request) {
	if err := initSEO(); err != nil {
		http.Error(w, "seo database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	id, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var pid int64
	if err := seoDB.QueryRow(`SELECT project_id FROM crawls WHERE id = ?`, id).Scan(&pid); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	resp := seoFindingsResponse{
		CrawlID:   id,
		ProjectID: pid,
		Critical:  seoIssueR.FindIssuesByTypeAndPriority(id, 1),
		Alert:     seoIssueR.FindIssuesByTypeAndPriority(id, 2),
		Warning:   seoIssueR.FindIssuesByTypeAndPriority(id, 3),
		Note:      "Use GET /api/seo/crawl/{id}/issues/pages?type=ERROR_TYPE to list affected URLs for one issue type.",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

type seoIssuePagesResponse struct {
	CrawlID   int64                      `json:"crawl_id"`
	IssueType string                     `json:"issue_type"`
	PageCount int                        `json:"page_count"`
	Pages     []store.PageReportIssueRow `json:"pages"`
}

// GetSEOPageDetail returns the full evidence payload for one crawled page: all stored field
// values (title text, TTFB, depth, robots, canonical …) plus every image with its alt text,
// hreflang tags, and the list of SEO issue types detected on that page.
// The client can use these raw values to show the customer exactly what triggered each issue.
func GetSEOPageDetail(w http.ResponseWriter, r *http.Request) {
	if err := initSEO(); err != nil {
		http.Error(w, "seo database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	crawlID, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil || crawlID < 1 {
		http.Error(w, "invalid crawl id", http.StatusBadRequest)
		return
	}
	pageID, err := strconv.ParseInt(vars["page_id"], 10, 64)
	if err != nil || pageID < 1 {
		http.Error(w, "invalid page id", http.StatusBadRequest)
		return
	}
	// Verify the crawl exists (prevents probing arbitrary crawl IDs).
	var crawlOK int
	if err := seoDB.QueryRow(`SELECT 1 FROM crawls WHERE id = ?`, crawlID).Scan(&crawlOK); err != nil {
		http.Error(w, "crawl not found", http.StatusNotFound)
		return
	}
	detail, err := seoPageR.GetPageDetail(crawlID, pageID)
	if err != nil {
		http.Error(w, "page not found", http.StatusNotFound)
		return
	}
	type pageDetailResponse struct {
		CrawlID int64 `json:"crawl_id"`
		*store.PageDetailRow
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pageDetailResponse{CrawlID: crawlID, PageDetailRow: detail})
}

// GetSEOPagesForIssue lists URLs/titles for pages that have a given issue_types.type (e.g. ERROR_EMPTY_TITLE).
func GetSEOPagesForIssue(w http.ResponseWriter, r *http.Request) {
	if err := initSEO(); err != nil {
		http.Error(w, "seo database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	id, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	issueType := r.URL.Query().Get("type")
	if issueType == "" {
		http.Error(w, "query parameter type is required (issue_types.type, e.g. ERROR_EMPTY_TITLE)", http.StatusBadRequest)
		return
	}
	var crawlOK int
	if err := seoDB.QueryRow(`SELECT 1 FROM crawls WHERE id = ?`, id).Scan(&crawlOK); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	pages, err := seoPageR.ListPageReportsForIssueType(id, issueType, limit)
	if err != nil {
		log.Printf("seo ListPageReportsForIssueType: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(seoIssuePagesResponse{
		CrawlID:   id,
		IssueType: issueType,
		PageCount: len(pages),
		Pages:     pages,
	})
}
