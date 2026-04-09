package page

import (
	"net/http"

	"temp-email/internal/seocrawl/issues/errors"
	"temp-email/internal/seocrawl/models"

	"golang.org/x/net/html"
)

// Returns a report_manager.PageIssueReporter with a callback function that
// checks if the TTFB. The callback returns true if the page's time to first byte is slow.
func NewSlowTTFBReporter() *models.PageIssueReporter {
	c := func(pageReport *models.PageReport, htmlNode *html.Node, header *http.Header) bool {
		return pageReport.TTFB > 800
	}

	return &models.PageIssueReporter{
		ErrorType: errors.ErrorSlowTTFB,
		Callback:  c,
	}
}
