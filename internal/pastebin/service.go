package pastebin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
)

// Service orchestrates paste creation, retrieval, and deletion.
type Service struct {
	cfg     *Config
	meta    MetaStore
	content ContentStore
}

// NewService creates a pastebin service. Uses R2 for content if configured; falls back to filesystem (TODO) or errors.
func NewService(cfg *Config) (*Service, error) {
	meta, err := NewSQLiteStore(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("sqlite: %w", err)
	}
	var content ContentStore
	switch cfg.Storage {
	case "r2":
		content, err = NewR2Store(cfg)
		if err != nil {
			return nil, fmt.Errorf("r2: %w", err)
		}
	case "filesystem", "fs":
		dir := os.Getenv("PASTEBIN_CONTENT_DIR")
		if dir == "" {
			dir = "/tmp/pastebin-content"
		}
		content, err = NewFSStore(dir)
		if err != nil {
			return nil, fmt.Errorf("filesystem: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported storage: %s (use r2 or filesystem)", cfg.Storage)
	}
	return &Service{cfg: cfg, meta: meta, content: content}, nil
}

// CreateRequest holds input for creating a paste.
type CreateRequest struct {
	Content       []byte
	Filename      string
	ContentType   string
	Title         string
	Syntax        string
	Expiry        string
	Visibility    string
	BurnAfterRead bool
	Passphrase    string
	Slug          string
	SessionID     string
	APIKeyID      string
	IsFile        bool
}

// CreateResponse is returned after creating a paste.
type CreateResponse struct {
	ID            string  `json:"id"`
	URL           string  `json:"url"`
	RawURL        string  `json:"rawUrl"`
	ExpiresAt     *string `json:"expiresAt,omitempty"`
	DeleteToken   string  `json:"deleteToken,omitempty"`
	BurnAfterRead bool    `json:"burnAfterRead"`
}

// Create creates a new paste.
func (s *Service) Create(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	size := int64(len(req.Content))
	if req.IsFile {
		if size > s.cfg.MaxFileSizeBytes() {
			return nil, ErrContentTooLarge
		}
	} else {
		if size > s.cfg.MaxTextSizeBytes() {
			return nil, ErrContentTooLarge
		}
	}
	if s.cfg.Blocklist != nil && s.cfg.Blocklist.Blocked(string(req.Content)) {
		return nil, ErrBlocked
	}
	expiryStr := req.Expiry
	if expiryStr == "" {
		expiryStr = s.cfg.DefaultExpiry
	}
	expiresAt, err := ParseExpiry(expiryStr)
	if err != nil {
		return nil, err
	}
	id := req.Slug
	if id == "" {
		id = generateID(s.cfg.SlugLength)
	} else {
		exists, err := s.meta.Exists(ctx, id)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, ErrSlugTaken
		}
	}
	pasteType := "text"
	contentType := "text/plain; charset=utf-8"
	filename := ""
	size = int64(len(req.Content))
	if req.IsFile {
		pasteType = "file"
		contentType = req.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		filename = req.Filename
	}
	visibility := req.Visibility
	if visibility == "" {
		visibility = "unlisted"
	}
	deleteToken := uuid.New().String()
	deleteTokenHash := hashToken(deleteToken)
	contentBytes := req.Content
	encrypted := false
	if visibility == "private" && req.Passphrase != "" {
		salt := make([]byte, SaltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		key := DeriveKeyFromPassphrase(req.Passphrase, salt)
		encBytes, err := EncryptAESGCM(key, req.Content)
		if err != nil {
			return nil, err
		}
		contentBytes = append(salt, encBytes...)
		encrypted = true
	} else if len(s.cfg.EncryptionKey) == 32 {
		encBytes, err := EncryptAESGCM(s.cfg.EncryptionKey, req.Content)
		if err != nil {
			return nil, err
		}
		contentBytes = encBytes
		encrypted = true
	}

	p := &Paste{
		ID:              id,
		Type:            pasteType,
		Filename:        filename,
		ContentType:     contentType,
		Size:            int64(len(req.Content)),
		Title:           req.Title,
		Syntax:          req.Syntax,
		Visibility:      visibility,
		ExpiresAt:       expiresAt,
		CreatedAt:       time.Now(),
		BurnAfterRead:   req.BurnAfterRead,
		Encrypted:       encrypted,
		SessionID:       req.SessionID,
		APIKeyID:        req.APIKeyID,
		DeleteTokenHash: deleteTokenHash,
	}
	if err := s.content.Put(ctx, id, contentBytes, contentType); err != nil {
		return nil, err
	}
	if err := s.meta.Save(ctx, p); err != nil {
		_ = s.content.Delete(ctx, id)
		return nil, err
	}
	resp := &CreateResponse{
		ID:            id,
		URL:           s.cfg.BaseURL + "/api/pastebin/" + id,
		RawURL:        s.cfg.BaseURL + "/api/pastebin/" + id + "/raw",
		DeleteToken:   deleteToken,
		BurnAfterRead: req.BurnAfterRead,
	}
	if expiresAt != nil {
		t := expiresAt.UTC().Format(time.RFC3339)
		resp.ExpiresAt = &t
	}
	return resp, nil
}

// Get retrieves a paste by ID. Returns content and metadata. Checks expiry and burn-after-read.
func (s *Service) Get(ctx context.Context, id string, passphrase string) (*Paste, error) {
	p, err := s.meta.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if p.ExpiresAt != nil && p.ExpiresAt.Before(time.Now()) {
		_ = s.Delete(ctx, id, "") // lazy cleanup
		return nil, ErrExpired
	}
	if p.Visibility == "private" && passphrase == "" {
		return nil, ErrPassphraseRequired
	}
	content, _, err := s.content.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if p.Encrypted {
		if p.Visibility == "private" && passphrase != "" {
			if len(content) < SaltSize {
				return nil, ErrWrongPassphrase
			}
			salt := content[:SaltSize]
			key := DeriveKeyFromPassphrase(passphrase, salt)
			plain, err := DecryptAESGCM(key, content[SaltSize:])
			if err != nil {
				return nil, ErrWrongPassphrase
			}
			p.Content = plain
		} else if len(s.cfg.EncryptionKey) == 32 {
			plain, err := DecryptAESGCM(s.cfg.EncryptionKey, content)
			if err != nil {
				return nil, err
			}
			p.Content = plain
		} else {
			p.Content = content
		}
	} else {
		p.Content = content
	}
	_ = s.meta.IncrementViewCount(ctx, id)
	p.ViewCount++ // reflect increment in response
	if p.BurnAfterRead {
		// Bypass token check - we're burning after read
		_ = s.content.Delete(ctx, id)
		_ = s.meta.Delete(ctx, id)
	}
	return p, nil
}

// GetMeta returns metadata only (no content).
func (s *Service) GetMeta(ctx context.Context, id string) (*Paste, error) {
	return s.meta.Get(ctx, id)
}

// Delete removes a paste. deleteToken must match if the paste has one.
func (s *Service) Delete(ctx context.Context, id string, deleteToken string) error {
	p, err := s.meta.Get(ctx, id)
	if err != nil {
		return err
	}
	if p.DeleteTokenHash != "" {
		if hashToken(deleteToken) != p.DeleteTokenHash {
			return ErrNotFound // don't reveal existence
		}
	}
	_ = s.content.Delete(ctx, id)
	return s.meta.Delete(ctx, id)
}

// CreateAPIKey creates a new API key. Returns raw key (pk_xxx) shown once.
func (s *Service) CreateAPIKey(ctx context.Context) (rawKey, keyID string, err error) {
	keyID = uuid.New().String()
	rawKey = "pk_" + generateID(24)
	keyHash := hashToken(rawKey)
	if err := s.meta.CreateAPIKey(ctx, keyID, keyHash); err != nil {
		return "", "", err
	}
	return rawKey, keyID, nil
}

// ResolveAPIKey returns apiKeyID if the raw key is valid.
func (s *Service) ResolveAPIKey(ctx context.Context, rawKey string) (string, error) {
	return s.meta.GetAPIKeyID(ctx, hashToken(rawKey))
}

// HealthCheck verifies storage connectivity.
func (s *Service) HealthCheck(ctx context.Context) error {
	_, err := s.meta.Get(ctx, "__health__")
	if err != nil && err != ErrNotFound {
		return err
	}
	return nil
}

// GetStats returns aggregate statistics.
func (s *Service) GetStats(ctx context.Context) (*Stats, error) {
	return s.meta.Stats(ctx)
}

// StartCleanup runs background goroutine to delete expired pastes.
func (s *Service) StartCleanup(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			ids, err := s.meta.ListExpired(context.Background(), 100)
			if err != nil || len(ids) == 0 {
				continue
			}
			for _, id := range ids {
				_ = s.Delete(context.Background(), id, "")
			}
		}
	}()
}

// ListMine returns pastes for the given session or API key.
func (s *Service) ListMine(ctx context.Context, sessionID, apiKeyID string, limit, offset int) ([]*PasteMeta, error) {
	if sessionID != "" {
		return s.meta.ListBySession(ctx, sessionID, limit, offset)
	}
	if apiKeyID != "" {
		return s.meta.ListByAPIKey(ctx, apiKeyID, limit, offset)
	}
	return nil, nil
}

// ListRecent returns recent public pastes (no auth required).
func (s *Service) ListRecent(ctx context.Context, limit, offset int) ([]*PasteMeta, error) {
	return s.meta.ListRecent(ctx, limit, offset)
}

func generateID(length int) string {
	if length <= 0 {
		length = 8
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return uuid.New().String()[:length]
	}
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
