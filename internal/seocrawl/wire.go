package seocrawl

import (
	"database/sql"

	"temp-email/internal/seocrawl/config"
	"temp-email/internal/seocrawl/issues/multipage"
	"temp-email/internal/seocrawl/issues/page"
	"temp-email/internal/seocrawl/services"
	"temp-email/internal/seocrawl/store"
)

// Repo bundles store types for CrawlerService and CrawlerHandler.
type Repo struct {
	*store.CrawlRepository
	*store.IssueRepository
	*store.PageReportRepository
}

// OpenSQLite opens the DB, enables foreign keys, applies schema, and sets pool size.
func OpenSQLite(path string, maxOpenConns int) (*sql.DB, error) {
	if maxOpenConns < 1 {
		maxOpenConns = 1
	}
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(maxOpenConns)
	if err := store.Migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// NewCrawlerService wires SEOnaut-equivalent page + multipage issue reporters (SQLite-backed).
func NewCrawlerService(db *sql.DB, cfg *config.CrawlerConfig) *services.CrawlerService {
	if cfg == nil {
		cfg = config.LoadCrawlerFromEnv()
	}
	cr := &store.CrawlRepository{DB: db}
	ir := &store.IssueRepository{DB: db}
	pr := &store.PageReportRepository{DB: db}
	repo := &Repo{CrawlRepository: cr, IssueRepository: ir, PageReportRepository: pr}

	services.SetHTMLMaxBodyBytes(cfg.MaxBodyBytes)

	rm := services.NewReportManager(ir)
	for _, r := range page.GetAllReporters(cfg.DOMMaxNodes) {
		rm.AddPageReporter(r)
	}
	sr := multipage.NewSqlReporter(db)
	for _, r := range sr.GetAllReporters() {
		rm.AddMultipageReporter(r)
	}

	broker := services.NewPubSubBroker()
	ch := services.NewCrawlerHandler(pr, broker, rm)
	if cfg.Agent == "" {
		cfg.Agent = "Mozilla/5.0 (compatible; SEOCrawlBot/1.0)"
	}

	return services.NewCrawlerService(repo, services.CrawlerServicesContainer{
		Broker:         broker,
		ReportManager:  rm,
		CrawlerHandler: ch,
		ArchiveService: nil,
		Config:         cfg,
	})
}
