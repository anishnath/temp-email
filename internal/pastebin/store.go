package pastebin

import (
	"context"
)

// ContentStore handles raw content (R2 or filesystem).
type ContentStore interface {
	Put(ctx context.Context, key string, data []byte, contentType string) error
	Get(ctx context.Context, key string) ([]byte, string, error)
	Delete(ctx context.Context, key string) error
}

// Stats holds aggregate pastebin statistics.
type Stats struct {
	TotalPastes   int64 `json:"totalPastes"`
	TotalText     int64 `json:"totalText"`
	TotalFiles    int64 `json:"totalFiles"`
	TotalSize     int64 `json:"totalSize"`
	TotalViews    int64 `json:"totalViews"`
	APIKeysCount  int64 `json:"apiKeysCount"`
	PastesLast24h int64 `json:"pastesLast24h"`
	PastesLast7d  int64 `json:"pastesLast7d"`
}

// MetaStore handles paste metadata (SQLite).
type MetaStore interface {
	Save(ctx context.Context, p *Paste) error
	Get(ctx context.Context, id string) (*Paste, error)
	Exists(ctx context.Context, id string) (bool, error)
	Delete(ctx context.Context, id string) error
	ListBySession(ctx context.Context, sessionID string, limit, offset int) ([]*PasteMeta, error)
	ListByAPIKey(ctx context.Context, apiKeyID string, limit, offset int) ([]*PasteMeta, error)
	ListRecent(ctx context.Context, limit, offset int) ([]*PasteMeta, error)
	ListExpired(ctx context.Context, limit int) ([]string, error)
	CreateAPIKey(ctx context.Context, id, keyHash string) error
	GetAPIKeyID(ctx context.Context, keyHash string) (string, error)
	Stats(ctx context.Context) (*Stats, error)
	IncrementViewCount(ctx context.Context, id string) error
}
