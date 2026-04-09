package config

import (
	"os"
	"strconv"
	"strings"
)

// CrawlerConfig holds all tunable SEO crawler settings (loaded from environment).
type CrawlerConfig struct {
	Agent string

	// CrawlLimit is the max number of page reports per crawl.
	CrawlLimit int
	// ClientTimeoutSeconds is the HTTP client timeout for each request.
	ClientTimeoutSeconds int
	// CrawlerTimeoutHours is the max wall-clock time for a full crawl.
	CrawlerTimeoutHours int
	// RandomDelayMaxMs is the upper bound (exclusive +1 in rand) for sleep before each fetch.
	RandomDelayMaxMs int
	// ConsumerThreads is the number of concurrent fetch workers.
	ConsumerThreads int
	// MaxBodyBytes is the max response body read when building a page report.
	MaxBodyBytes int64
	// DOMMaxNodes triggers ERROR_DOM_SIZE when HTML exceeds this node count.
	DOMMaxNodes int
	// LastCrawlsLimit is how many past crawls GetLastCrawls pads to (SEOnaut UI parity).
	LastCrawlsLimit int
	// DBMaxOpenConns is passed to sql.DB.SetMaxOpenConns for SQLite (typically 1).
	DBMaxOpenConns int
}

// LoadCrawlerFromEnv reads SEO_* variables. Omitted vars use conservative defaults for a free/public service.
func LoadCrawlerFromEnv() *CrawlerConfig {
	c := &CrawlerConfig{
		Agent:                strings.TrimSpace(getenv("SEO_CRAWLER_USER_AGENT", "Mozilla/5.0 (compatible; SEOCrawlBot/1.0)")),
		CrawlLimit:           getenvInt("SEO_CRAWL_MAX_URLS", 20000),
		ClientTimeoutSeconds: getenvInt("SEO_HTTP_CLIENT_TIMEOUT_SEC", 10),
		CrawlerTimeoutHours:  getenvInt("SEO_CRAWL_MAX_RUNTIME_HOURS", 2),
		RandomDelayMaxMs:     getenvInt("SEO_CRAWL_RANDOM_DELAY_MAX_MS", 1500),
		ConsumerThreads:      getenvInt("SEO_CRAWL_WORKER_THREADS", 2),
		MaxBodyBytes:         getenvInt64("SEO_HTML_MAX_BODY_BYTES", 10*1024*1024),
		DOMMaxNodes:          getenvInt("SEO_DOM_MAX_NODES", 1500),
		LastCrawlsLimit:      getenvInt("SEO_LAST_CRAWLS_LIMIT", 5),
		DBMaxOpenConns:       getenvInt("SEO_DB_MAX_OPEN_CONNS", 1),
	}
	clampCrawler(c)
	return c
}

func clampCrawler(c *CrawlerConfig) {
	if c.CrawlLimit < 1 {
		c.CrawlLimit = 1
	}
	if c.CrawlLimit > 100000 {
		c.CrawlLimit = 100000
	}
	if c.ClientTimeoutSeconds < 1 {
		c.ClientTimeoutSeconds = 1
	}
	if c.ClientTimeoutSeconds > 600 {
		c.ClientTimeoutSeconds = 600
	}
	if c.CrawlerTimeoutHours < 1 {
		c.CrawlerTimeoutHours = 1
	}
	if c.CrawlerTimeoutHours > 48 {
		c.CrawlerTimeoutHours = 48
	}
	if c.RandomDelayMaxMs < 0 {
		c.RandomDelayMaxMs = 0
	}
	if c.RandomDelayMaxMs > 10000 {
		c.RandomDelayMaxMs = 10000
	}
	if c.ConsumerThreads < 1 {
		c.ConsumerThreads = 1
	}
	if c.ConsumerThreads > 32 {
		c.ConsumerThreads = 32
	}
	const minBody = 64 * 1024
	const maxBody = 100 * 1024 * 1024
	if c.MaxBodyBytes < minBody {
		c.MaxBodyBytes = minBody
	}
	if c.MaxBodyBytes > maxBody {
		c.MaxBodyBytes = maxBody
	}
	if c.DOMMaxNodes < 100 {
		c.DOMMaxNodes = 100
	}
	if c.DOMMaxNodes > 100000 {
		c.DOMMaxNodes = 100000
	}
	if c.LastCrawlsLimit < 1 {
		c.LastCrawlsLimit = 1
	}
	if c.LastCrawlsLimit > 100 {
		c.LastCrawlsLimit = 100
	}
	if c.DBMaxOpenConns < 1 {
		c.DBMaxOpenConns = 1
	}
	if c.DBMaxOpenConns > 16 {
		c.DBMaxOpenConns = 16
	}
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getenvInt64(key string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}
