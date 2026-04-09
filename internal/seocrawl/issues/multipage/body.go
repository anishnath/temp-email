package multipage

import (
	"temp-email/internal/seocrawl/issues/errors"
	"temp-email/internal/seocrawl/models"
)

// Creates a MultipageIssueReporter object that contains the SQL query to check for pages with identical titles.
// It considers factors such as the HTTP status code, media type and whether they are canonical or not.
func (sr *SqlReporter) DuplicatedContent(c *models.Crawl) *models.MultipageIssueReporter {
	query := `
		SELECT id
		FROM pagereports
		WHERE body_hash IN (
			SELECT body_hash
			FROM pagereports
			WHERE crawl_id = ? AND media_type = "text/html" AND body_hash <> ""
			GROUP BY body_hash
			HAVING COUNT(*) > 1
		) AND crawl_id = ? AND media_type = "text/html" AND body_hash <> ""`

	return &models.MultipageIssueReporter{
		Pstream:   sr.pageReportsQuery(query, c.Id, c.Id),
		ErrorType: errors.ErrorDuplicatedContent,
	}
}
