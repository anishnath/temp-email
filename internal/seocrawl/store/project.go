package store

import (
	"temp-email/internal/seocrawl/models"
)

// InsertProject inserts a crawl project row and sets p.Id (user_id = 1 system user).
func (ds *CrawlRepository) InsertProject(p *models.Project) error {
	const q = `INSERT INTO projects (
		url, ignore_robotstxt, follow_nofollow, include_noindex, crawl_sitemap,
		allow_subdomains, basic_auth, user_id, check_external_links, archive, user_agent
	) VALUES (?,?,?,?,?,?,?,?,?,?,?)`
	stmt, err := ds.DB.Prepare(q)
	if err != nil {
		return err
	}
	defer stmt.Close()
	uid := int64(1)
	if p.UserAgent == "" {
		p.UserAgent = "Mozilla/5.0 (compatible; SEOCrawlBot/1.0)"
	}
	res, err := stmt.Exec(
		p.URL,
		p.IgnoreRobotsTxt,
		p.FollowNofollow,
		p.IncludeNoindex,
		p.CrawlSitemap,
		p.AllowSubdomains,
		p.BasicAuth,
		uid,
		p.CheckExternalLinks,
		p.Archive,
		p.UserAgent,
	)
	if err != nil {
		return err
	}
	p.Id, err = res.LastInsertId()
	return err
}
