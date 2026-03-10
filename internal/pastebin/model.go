package pastebin

import "time"

// Paste represents a paste (text or file) with metadata.
type Paste struct {
	ID              string
	Type            string // "text" | "file"
	Content         []byte // in-memory only; stored in R2
	Filename        string
	ContentType     string
	Size            int64
	Title           string
	Syntax          string
	Visibility      string // "public" | "unlisted" | "private"
	ExpiresAt       *time.Time
	CreatedAt       time.Time
	Encrypted       bool
	BurnAfterRead   bool
	SessionID       string
	APIKeyID        string
	DeleteTokenHash string
	ViewCount       int64
}

// PasteMeta is metadata only (for listing, no content).
type PasteMeta struct {
	ID          string
	Type        string
	Filename    string
	ContentType string
	Size        int64
	Title       string
	Syntax      string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	URL         string
	ViewCount   int64
}
