package services

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"temp-email/internal/seocrawl/config"
	"temp-email/internal/seocrawl/crawler"
	"temp-email/internal/seocrawl/models"
)

type CrawlerServiceRepository interface {
	SaveCrawl(models.Project) (*models.Crawl, error)
	GetLastCrawl(p *models.Project) models.Crawl
	GetLastCrawls(models.Project, int) []models.Crawl
	DeleteCrawlData(c *models.Crawl)

	CountIssuesByPriority(int64, int) int
	UpdateCrawl(*models.Crawl)
}

type CrawlerServicesContainer struct {
	Broker         *Broker
	ReportManager  *ReportManager
	CrawlerHandler *CrawlerHandler
	ArchiveService *ArchiveService
	Config         *config.CrawlerConfig
}

type CrawlerService struct {
	repository     CrawlerServiceRepository
	config         *config.CrawlerConfig
	broker         *Broker
	reportManager  *ReportManager
	crawlerHandler *CrawlerHandler
	ArchiveService *ArchiveService
	crawlers       map[int64]*crawler.Crawler
	lock           *sync.RWMutex
}

func NewCrawlerService(r CrawlerServiceRepository, s CrawlerServicesContainer) *CrawlerService {
	return &CrawlerService{
		repository:     r,
		broker:         s.Broker,
		config:         s.Config,
		reportManager:  s.ReportManager,
		crawlerHandler: s.CrawlerHandler,
		ArchiveService: s.ArchiveService,
		crawlers:       make(map[int64]*crawler.Crawler),
		lock:           &sync.RWMutex{},
	}
}

// StartCrawler creates a new crawler and crawls the project's URL.
// It returns the new crawl row immediately; work continues in the background.
func (s *CrawlerService) StartCrawler(p models.Project, b models.BasicAuth) (*models.Crawl, error) {
	previousCrawl := s.repository.GetLastCrawl(&p)
	crawl, err := s.repository.SaveCrawl(p)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(p.URL)
	if err != nil {
		return nil, err
	}

	if u.Path == "" {
		u.Path = "/"
	}

	c, err := s.addCrawler(u, &p, &b)
	if err != nil {
		return nil, err
	}

	go func() {
		defer s.removeCrawler(&p)
		defer s.repository.DeleteCrawlData(&previousCrawl)

		callback := s.crawlerHandler.responseCallback(crawl, &p, c)

		if p.Archive && s.ArchiveService != nil {
			archiver, err := s.ArchiveService.GetArchiveWriter(&p)
			if err != nil {
				log.Printf("Failed to create archive: %v", err)
			} else {
				defer archiver.Close()
				callback = s.crawlerHandler.archiveWrapper(callback, archiver)
			}
		}

		c.OnResponse(callback)

		log.Printf("Crawling %s...", p.URL)
		c.AddRequest(&crawler.RequestMessage{URL: u, Data: crawlerData{}})

		// Calling Start() initiates the website crawling process and
		// blocks execution until the crawling is complete.
		c.Start()

		crawl.RobotstxtExists = c.RobotstxtExists()
		crawl.SitemapExists = c.SitemapExists()
		crawl.SitemapIsBlocked = c.SitemapIsBlocked()
		crawl.End = time.Now()

		s.broker.Publish(fmt.Sprintf("crawl-%d", p.Id), &models.Message{Name: "IssuesInit"})
		s.reportManager.CreateMultipageIssues(crawl)

		crawl.IssuesEnd = time.Now()
		crawl.CriticalIssues = s.repository.CountIssuesByPriority(crawl.Id, Critical)
		crawl.AlertIssues = s.repository.CountIssuesByPriority(crawl.Id, Alert)
		crawl.WarningIssues = s.repository.CountIssuesByPriority(crawl.Id, Warning)
		crawl.TotalIssues = crawl.CriticalIssues + crawl.AlertIssues + crawl.WarningIssues

		s.repository.UpdateCrawl(crawl)
		s.broker.Publish(fmt.Sprintf("crawl-%d", p.Id), &models.Message{Name: "CrawlEnd", Data: crawl.TotalURLs})
		log.Printf("Crawled %d urls in %s", crawl.TotalURLs, p.URL)
	}()

	return crawl, nil
}

// Get a slice with 'LastCrawlsLimit' number of the crawls
func (s *CrawlerService) GetLastCrawls(p models.Project) []models.Crawl {
	limit := s.config.LastCrawlsLimit
	if limit < 1 {
		limit = 5
	}
	crawls := s.repository.GetLastCrawls(p, limit)

	for len(crawls) < limit {
		crawls = append(crawls, models.Crawl{Start: time.Now()})
	}

	return crawls
}

// StopCrawler stops a crawler. If the crawler does not exsit it will just return.
func (s *CrawlerService) StopCrawler(p models.Project) {
	s.lock.Lock()
	defer s.lock.Unlock()

	crawler, ok := s.crawlers[p.Id]
	if !ok {
		return
	}

	crawler.Stop()
}

// StopCrawlerByProjectID stops the crawler running for the given project ID.
// Returns true if a running crawler was found and signalled to stop, false if
// no crawler was active for that project (already finished or unknown).
func (s *CrawlerService) StopCrawlerByProjectID(projectID int64) bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	c, ok := s.crawlers[projectID]
	if !ok {
		return false
	}
	c.Stop()
	return true
}

// AddCrawler creates a new project crawler and adds it to the crawlers map. It returns the crawler
// on success otherwise it returns an error indicating the crawler already exists or there was an
// error creating it.
func (s *CrawlerService) addCrawler(u *url.URL, p *models.Project, b *models.BasicAuth) (*crawler.Crawler, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, ok := s.crawlers[p.Id]; ok {
		return nil, errors.New("project is already being crawled")
	}

	ct := s.config.ClientTimeoutSeconds
	if ct < 1 {
		ct = 10
	}
	cl := s.config.CrawlLimit
	if cl < 1 {
		cl = 20000
	}
	options := &crawler.Options{
		CrawlLimit:          cl,
		IgnoreRobotsTxt:     p.IgnoreRobotsTxt,
		FollowNofollow:      p.FollowNofollow,
		IncludeNoindex:      p.IncludeNoindex,
		CrawlSitemap:        p.CrawlSitemap,
		AllowSubdomains:     p.AllowSubdomains,
		RandomDelayMaxMs:    s.config.RandomDelayMaxMs,
		CrawlerTimeoutHours: s.config.CrawlerTimeoutHours,
		ConsumerThreads:     s.config.ConsumerThreads,
	}

	mainDomain := strings.TrimPrefix(u.Host, "www.")

	httpClient := &http.Client{
		Timeout: time.Duration(ct) * time.Second,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Make sure the user agent is not empty
	if p.UserAgent == "" {
		p.UserAgent = s.config.Agent
	}

	client := crawler.NewBasicClient(&crawler.ClientOptions{
		UserAgent:        p.UserAgent,
		BasicAuthDomains: []string{mainDomain, "www." + mainDomain},
		AuthUser:         b.AuthUser,
		AuthPass:         b.AuthPass,
	}, httpClient)

	// Creates a new crawler with the crawler's response handler.
	s.crawlers[p.Id] = crawler.NewCrawler(u, options, client)

	return s.crawlers[p.Id], nil
}

// RemoveCrawler removes a project's crawler from the crawlers map.
func (s *CrawlerService) removeCrawler(p *models.Project) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.crawlers, p.Id)
}
