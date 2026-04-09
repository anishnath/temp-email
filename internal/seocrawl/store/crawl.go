package store

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"temp-email/internal/seocrawl/models"
)

// CrawlRepository persists crawl sessions (SQLite).
type CrawlRepository struct {
	DB *sql.DB
}

// GetCrawlByID loads a crawl row by primary key (SQLite-friendly time columns).
func (ds *CrawlRepository) GetCrawlByID(id int64) (models.Crawl, error) {
	const q = `
		SELECT id, start, end, total_urls, total_issues, issues_end,
			critical_issues, alert_issues, warning_issues,
			blocked_by_robotstxt, noindex, robotstxt_exists, sitemap_exists, sitemap_blocked
		FROM crawls WHERE id = ?`
	var c models.Crawl
	var startS, endS, issuesS sql.NullString
	var rtxt, smap, smb int
	err := ds.DB.QueryRow(q, id).Scan(
		&c.Id, &startS, &endS, &c.TotalURLs, &c.TotalIssues, &issuesS,
		&c.CriticalIssues, &c.AlertIssues, &c.WarningIssues,
		&c.BlockedByRobotstxt, &c.Noindex, &rtxt, &smap, &smb,
	)
	c.RobotstxtExists = rtxt != 0
	c.SitemapExists = smap != 0
	c.SitemapIsBlocked = smb != 0
	if err != nil {
		return c, err
	}
	if startS.Valid {
		c.Start, _ = parseSQLiteTime(startS.String)
	}
	c.Crawling = !endS.Valid || strings.TrimSpace(endS.String) == ""
	if endS.Valid {
		c.End, _ = parseSQLiteTime(endS.String)
	}
	if issuesS.Valid {
		c.IssuesEnd, _ = parseSQLiteTime(issuesS.String)
	}
	return c, nil
}

func parseSQLiteTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC)
}

// SaveCrawl inserts a new crawl into the database and returns a new Crawl model with
// the data provided by the project.
func (ds *CrawlRepository) SaveCrawl(p models.Project) (*models.Crawl, error) {
	stmt, _ := ds.DB.Prepare("INSERT INTO crawls (project_id) VALUES (?)")
	defer stmt.Close()
	res, err := stmt.Exec(p.Id)

	if err != nil {
		return nil, err
	}

	cid, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &models.Crawl{
		Id:        cid,
		ProjectId: p.Id,
		URL:       p.URL,
		Start:     time.Now(),
	}, nil
}

// GetLastCrawl returns a Crawl model with the last crawl stored for an specific project.
func (ds *CrawlRepository) GetLastCrawl(p *models.Project) models.Crawl {
	query := `
		SELECT
			id,
			start,
			end,
			total_urls,
			total_issues,
			critical_issues,
			alert_issues,
			warning_issues,
			issues_end,
			robotstxt_exists,
			sitemap_exists,
			sitemap_blocked,
			links_internal_follow,
			links_internal_nofollow,
			links_external_follow,
			links_external_nofollow,
			links_sponsored,
			links_ugc
		FROM crawls
		WHERE project_id = ?
		ORDER BY start DESC LIMIT 1`

	row := ds.DB.QueryRow(query, p.Id)

	var endTime, issuesEndTime sql.NullTime
	crawl := models.Crawl{Crawling: true}
	err := row.Scan(
		&crawl.Id,
		&crawl.Start,
		&endTime, // &crawl.End,
		&crawl.TotalURLs,
		&crawl.TotalIssues,
		&crawl.CriticalIssues,
		&crawl.AlertIssues,
		&crawl.WarningIssues,
		&issuesEndTime, // &crawl.IssuesEnd,
		&crawl.RobotstxtExists,
		&crawl.SitemapExists,
		&crawl.SitemapIsBlocked,
		&crawl.InternalFollowLinks,
		&crawl.InternalNoFollowLinks,
		&crawl.ExternalFollowLinks,
		&crawl.ExternalNoFollowLinks,
		&crawl.SponsoredLinks,
		&crawl.UGCLinks,
	)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("GetLastCrawl project id %d: %v\n", p.Id, err)
	}

	if endTime.Valid && issuesEndTime.Valid {
		crawl.End = endTime.Time
		crawl.IssuesEnd = issuesEndTime.Time
		crawl.Crawling = false
	}

	return crawl
}

// GetLastCrawls returns a slice with a number of crawls for the specific project. The number of crawls
// to be returned is specified with the limit parameter.
func (ds *CrawlRepository) GetLastCrawls(p models.Project, limit int) []models.Crawl {
	query := `
		SELECT
			id,
			start,
			end,
			total_urls,
			total_issues,
			issues_end,
			critical_issues,
			alert_issues,
			warning_issues,
			blocked_by_robotstxt,
			noindex
		FROM crawls
		WHERE project_id = ?
		ORDER BY start DESC LIMIT ?`

	crawls := []models.Crawl{}
	rows, err := ds.DB.Query(query, p.Id, limit)
	if err != nil {
		log.Println(err)
	}

	for rows.Next() {
		endTime := sql.NullTime{}
		issuesEndTime := sql.NullTime{}
		crawl := models.Crawl{Crawling: true}
		err := rows.Scan(
			&crawl.Id,
			&crawl.Start,
			&endTime, // &crawl.End,
			&crawl.TotalURLs,
			&crawl.TotalIssues,
			&issuesEndTime, // &crawl.IssuesEnd,
			&crawl.CriticalIssues,
			&crawl.AlertIssues,
			&crawl.WarningIssues,
			&crawl.BlockedByRobotstxt,
			&crawl.Noindex,
		)
		if err != nil {
			log.Printf("GetLastCrawl: %v\n", err)
		}
		if endTime.Valid && issuesEndTime.Valid {
			crawl.End = endTime.Time
			crawl.IssuesEnd = issuesEndTime.Time
			crawl.Crawling = false
		}
		crawls = append([]models.Crawl{crawl}, crawls...)
	}

	return crawls
}

// CrawlListRow is a lightweight summary row returned by GET /api/seo/crawls.
type CrawlListRow struct {
	CrawlID        int64  `json:"crawl_id"`
	ProjectID      int64  `json:"project_id"`
	URL            string `json:"url"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at,omitempty"`
	Crawling       bool   `json:"crawling"`
	TotalURLs      int    `json:"total_urls"`
	TotalIssues    int    `json:"total_issues"`
	CriticalIssues int    `json:"critical_issues"`
	AlertIssues    int    `json:"alert_issues"`
	WarningIssues  int    `json:"warning_issues"`
}

// ListCrawls returns recent crawls joined with their project URL.
// If urlFilter is non-empty only crawls for that exact project URL are returned.
// Results are ordered newest-first; at most limit rows are returned (capped at 200).
func (ds *CrawlRepository) ListCrawls(urlFilter string, limit int) ([]CrawlListRow, error) {
	if limit < 1 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	args := []interface{}{}
	where := ""
	if urlFilter != "" {
		where = "WHERE projects.url = ?"
		args = append(args, urlFilter)
	}
	args = append(args, limit)

	q := fmt.Sprintf(`
		SELECT
			crawls.id,
			crawls.project_id,
			projects.url,
			crawls.start,
			crawls.end,
			crawls.total_urls,
			crawls.total_issues,
			crawls.critical_issues,
			crawls.alert_issues,
			crawls.warning_issues
		FROM crawls
		INNER JOIN projects ON projects.id = crawls.project_id
		%s
		ORDER BY crawls.start DESC
		LIMIT ?`, where)

	rows, err := ds.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CrawlListRow
	for rows.Next() {
		var r CrawlListRow
		var startS, endS sql.NullString
		if err := rows.Scan(
			&r.CrawlID, &r.ProjectID, &r.URL,
			&startS, &endS,
			&r.TotalURLs, &r.TotalIssues,
			&r.CriticalIssues, &r.AlertIssues, &r.WarningIssues,
		); err != nil {
			return nil, err
		}
		if startS.Valid {
			r.StartedAt = startS.String
		}
		r.Crawling = !endS.Valid || strings.TrimSpace(endS.String) == ""
		if endS.Valid && strings.TrimSpace(endS.String) != "" {
			r.FinishedAt = endS.String
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteCrawlData deletes all rows associated with a crawl (SQLite: single DELETE per table).
func (ds *CrawlRepository) DeleteCrawlData(crawl *models.Crawl) {
	if crawl == nil || crawl.Id == 0 {
		return
	}
	cid := crawl.Id
	tables := []string{
		"links", "external_links", "hreflangs", "issues", "images",
		"scripts", "styles", "iframes", "audios", "videos", "pagereports",
	}
	for _, t := range tables {
		q := fmt.Sprintf("DELETE FROM %s WHERE crawl_id = ?", t)
		if _, err := ds.DB.Exec(q, cid); err != nil {
			log.Printf("DeleteCrawlData: cid %d table %s %v\n", cid, t, err)
		}
	}
}

// DeleteProjectCrawls deletes all of the project's crawls and associated data.
func (ds *CrawlRepository) DeleteProjectCrawls(p *models.Project) {
	query := `
		SELECT
			id
		FROM crawls
		WHERE project_id = ?
	`

	rows, err := ds.DB.Query(query, p.Id)
	if err != nil {
		log.Printf("DeleteProjectCrawls Query: %v\n", err)
	}

	for rows.Next() {
		c := &models.Crawl{}
		if err := rows.Scan(&c.Id); err != nil {
			log.Printf("DeleteProjectCrawls: %v\n", err)
		}

		ds.DeleteCrawlData(c)
	}

	query = `DELETE FROM crawls WHERE project_id = ?`
	_, err = ds.DB.Exec(query, p.Id)
	if err != nil {
		log.Printf("deleting crawls for project %d: %v", p.Id, err)
		return
	}
}

// Deletes all crawls that are unfinished and have the issues_end field set to null.
// It cleans up the crawl data for each unfinished crawl before deleting it.
func (ds *CrawlRepository) DeleteUnfinishedCrawls() {
	query := `
		SELECT
			crawls.id
		FROM crawls
		WHERE crawls.issues_end IS NULL
	`
	count := 0

	rows, err := ds.DB.Query(query)
	if err != nil {
		log.Println(err)
		return
	}

	ids := []any{}
	placeholders := []string{}
	for rows.Next() {
		c := &models.Crawl{}
		err := rows.Scan(&c.Id)
		if err != nil {
			log.Printf("DeleteUnfinishedCrawls: %v\n", err)
			continue
		}

		count++
		ds.DeleteCrawlData(c)
		ids = append(ids, c.Id)
		placeholders = append(placeholders, "?")
	}

	if len(ids) == 0 {
		return
	}

	placeholdersStr := strings.Join(placeholders, ",")
	deleteQuery := fmt.Sprintf("DELETE FROM crawls WHERE id IN (%s)", placeholdersStr)
	_, err = ds.DB.Exec(deleteQuery, ids...)
	if err != nil {
		log.Printf("DeleteUnfinishedCrawls: %v", err)
	}

	log.Printf("Deleted %d unfinished crawls.", count)
}

// SaveIssuesCount stores the total number of issues as well as the total issues by priority for
// the crawl specified in the "crawlId" parameter.
func (ds *CrawlRepository) UpdateCrawl(crawl *models.Crawl) {
	query := `UPDATE
		crawls
		SET 
			end = ?,
			total_urls = ?,
			blocked_by_robotstxt = ?,
			noindex = ?,
			robotstxt_exists = ?,
			sitemap_exists = ?,
			sitemap_blocked = ?,
			links_internal_follow = ?,
			links_internal_nofollow = ?,
			links_external_follow = ?,
			links_external_nofollow = ?,
			links_sponsored = ?,
			links_ugc = ?,
			issues_end = ?,
			critical_issues = ?,
			alert_issues = ?,
			warning_issues = ?,
			total_issues = ?
		WHERE id = ?`

	_, err := ds.DB.Exec(
		query,
		crawl.End,
		crawl.TotalURLs,
		crawl.BlockedByRobotstxt,
		crawl.Noindex,
		crawl.RobotstxtExists,
		crawl.SitemapExists,
		crawl.SitemapIsBlocked,
		crawl.InternalFollowLinks,
		crawl.InternalNoFollowLinks,
		crawl.ExternalFollowLinks,
		crawl.ExternalNoFollowLinks,
		crawl.SponsoredLinks,
		crawl.UGCLinks,
		crawl.IssuesEnd,
		crawl.CriticalIssues,
		crawl.AlertIssues,
		crawl.WarningIssues,
		crawl.TotalIssues,
		crawl.Id,
	)
	if err != nil {
		log.Printf("SaveIssuesCount: %v\n", err)
	}
}
