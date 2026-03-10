package pastebin

import (
	"encoding/hex"
	"os"
	"strconv"
	"time"
)

// Config holds Pastebin configuration from environment variables.
type Config struct {
	Storage            string // "r2" | "filesystem"
	DBPath             string
	MaxTextSizeKB      int
	MaxFileSizeMB      int
	DefaultExpiry      string // "1h" | "24h" | "7d" | "30d" | "never"
	CleanupIntervalMin int    // 0 = lazy only
	SlugLength         int
	BaseURL            string
	R2AccountID        string
	R2AccessKeyID      string
	R2SecretAccessKey  string
	R2BucketName       string
	R2Endpoint         string
	EncryptionKey      []byte // 32 bytes for server-side encryption
	Blocklist          *Blocklist
}

// LoadConfig reads Pastebin configuration from environment.
func LoadConfig() *Config {
	maxTextKB := getEnvInt("PASTEBIN_MAX_TEXT_KB", 512)
	maxFileMB := getEnvInt("PASTEBIN_MAX_FILE_MB", 10)
	accountID := os.Getenv("R2_ACCOUNT_ID")
	r2Endpoint := os.Getenv("R2_ENDPOINT")
	if r2Endpoint == "" && accountID != "" {
		r2Endpoint = "https://" + accountID + ".r2.cloudflarestorage.com"
	}
	encKeyHex := os.Getenv("PASTEBIN_ENCRYPTION_KEY")
	var encKey []byte
	if len(encKeyHex) == 64 {
		encKey, _ = hex.DecodeString(encKeyHex)
	}
	return &Config{
		Storage:            getEnv("PASTEBIN_STORAGE", "r2"),
		DBPath:             getEnv("PASTEBIN_DB_PATH", "/tmp/pastebin.db"),
		MaxTextSizeKB:      maxTextKB,
		MaxFileSizeMB:      maxFileMB,
		DefaultExpiry:      getEnv("PASTEBIN_DEFAULT_EXPIRY", "24h"),
		CleanupIntervalMin: getEnvInt("PASTEBIN_CLEANUP_INTERVAL_MINUTES", 60),
		SlugLength:         getEnvInt("PASTEBIN_SLUG_LENGTH", 8),
		BaseURL:            getEnv("PASTEBIN_BASE_URL", "http://localhost:8080"),
		R2AccountID:        accountID,
		R2AccessKeyID:      os.Getenv("R2_ACCESS_KEY_ID"),
		R2SecretAccessKey:  os.Getenv("R2_SECRET_ACCESS_KEY"),
		R2BucketName:       getEnv("R2_BUCKET_NAME", "pastebin-storage"),
		R2Endpoint:         r2Endpoint,
		EncryptionKey:      encKey,
		Blocklist:          NewBlocklist(os.Getenv("PASTEBIN_BLOCKLIST")),
	}
}

// MaxTextSizeBytes returns max text size in bytes.
func (c *Config) MaxTextSizeBytes() int64 {
	return int64(c.MaxTextSizeKB) * 1024
}

// MaxFileSizeBytes returns max file size in bytes.
func (c *Config) MaxFileSizeBytes() int64 {
	return int64(c.MaxFileSizeMB) * 1024 * 1024
}

// ParseExpiry returns expiration time from a string like "1h", "24h", "7d", "30d", "never".
func ParseExpiry(s string) (*time.Time, error) {
	s = trimLower(s)
	if s == "" || s == "never" {
		return nil, nil
	}
	var d time.Duration
	switch s {
	case "1h":
		d = time.Hour
	case "24h":
		d = 24 * time.Hour
	case "7d":
		d = 7 * 24 * time.Hour
	case "30d":
		d = 30 * 24 * time.Hour
	default:
		return nil, ErrInvalidExpiry
	}
	t := time.Now().Add(d)
	return &t, nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}

func trimLower(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != ' ' && c != '\t' {
			b = append(b, c)
		}
	}
	return string(b)
}
