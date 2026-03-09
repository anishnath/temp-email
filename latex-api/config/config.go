package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds application configuration from environment variables.
type Config struct {
	Port               string
	LatexTempDir       string
	LatexTimeout       time.Duration
	WorkerPoolSize     int
	CleanupAfter       time.Duration
	MaxSourceSizeBytes int64
}

// Load reads configuration from environment variables.
func Load() *Config {
	timeoutSec := getEnvInt("LATEX_TIMEOUT_SECONDS", 30)
	cleanupMin := getEnvInt("CLEANUP_AFTER_MINUTES", 60)
	maxSourceKB := getEnvInt("MAX_SOURCE_SIZE_KB", 512)

	return &Config{
		Port:               getEnv("PORT", "8080"),
		LatexTempDir:       getEnv("LATEX_TEMP_DIR", "/tmp/latex-jobs"),
		LatexTimeout:       time.Duration(timeoutSec) * time.Second,
		WorkerPoolSize:     getEnvInt("WORKER_POOL_SIZE", 4),
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
