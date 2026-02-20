package latex

import (
	"os"
	"strconv"
	"time"
)

// Config holds LaTeX API configuration from environment variables.
type Config struct {
	LatexTempDir       string
	LatexTimeout       time.Duration
	WorkerPoolSize     int
	CleanupAfter       time.Duration
	MaxSourceSizeBytes int64
}

// LoadConfig reads LaTeX configuration from environment variables.
func LoadConfig() *Config {
	timeoutSec := getEnvInt("LATEX_TIMEOUT_SECONDS", 30)
	cleanupMin := getEnvInt("LATEX_CLEANUP_AFTER_MINUTES", 60)
	maxSourceKB := getEnvInt("LATEX_MAX_SOURCE_SIZE_KB", 512)

	return &Config{
		LatexTempDir:       getEnv("LATEX_TEMP_DIR", "/tmp/latex-jobs"),
		LatexTimeout:       time.Duration(timeoutSec) * time.Second,
		WorkerPoolSize:     getEnvInt("LATEX_WORKER_POOL_SIZE", 4),
		CleanupAfter:       time.Duration(cleanupMin) * time.Minute,
		MaxSourceSizeBytes: int64(maxSourceKB) * 1024,
	}
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
