package services

import (
	"errors"
	"net/http"

	"temp-email/internal/seocrawl/models"
)

// ArchiveService is optional WACZ export in SEOnaut; unused in temp-email (keep nil in CrawlerServicesContainer).
type ArchiveService struct{}

type noopWACZ struct{}

func (noopWACZ) AddRecord(*http.Response) {}
func (noopWACZ) Close() error             { return nil }

// GetArchiveWriter always fails; SEOnaut WACZ archiving is not wired in temp-email.
func (*ArchiveService) GetArchiveWriter(*models.Project) (noopWACZ, error) {
	return noopWACZ{}, errors.New("archive disabled")
}
