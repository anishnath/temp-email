package pastebin

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStore implements MetaStore using SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a SQLite metadata store and ensures schema exists.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			key_hash TEXT UNIQUE NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		);
		CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
		CREATE TABLE IF NOT EXISTS pastes (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL CHECK (type IN ('text', 'file')),
			filename TEXT,
			content_type TEXT,
			size INTEGER NOT NULL DEFAULT 0,
			title TEXT,
			syntax TEXT,
			visibility TEXT DEFAULT 'unlisted',
			expires_at TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			encrypted INTEGER DEFAULT 0,
			burn_after_read INTEGER DEFAULT 0,
			session_id TEXT,
			api_key_id TEXT,
			delete_token_hash TEXT,
			view_count INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_pastes_expires ON pastes(expires_at) WHERE expires_at IS NOT NULL;
		CREATE INDEX IF NOT EXISTS idx_pastes_created ON pastes(created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_pastes_session ON pastes(session_id) WHERE session_id IS NOT NULL;
		CREATE INDEX IF NOT EXISTS idx_pastes_api_key ON pastes(api_key_id) WHERE api_key_id IS NOT NULL;
	`)
	if err != nil {
		return err
	}
	// Add view_count to existing tables (ignored if column exists)
	_, _ = s.db.Exec("ALTER TABLE pastes ADD COLUMN view_count INTEGER NOT NULL DEFAULT 0")
	return nil
}

func (s *SQLiteStore) Save(ctx context.Context, p *Paste) error {
	expiresAt := ""
	if p.ExpiresAt != nil {
		expiresAt = p.ExpiresAt.UTC().Format("2006-01-02 15:04:05")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pastes (id, type, filename, content_type, size, title, syntax, visibility, expires_at, created_at, encrypted, burn_after_read, session_id, api_key_id, delete_token_hash, view_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		p.ID, p.Type, p.Filename, p.ContentType, p.Size, p.Title, p.Syntax, p.Visibility,
		expiresAt, p.CreatedAt.UTC().Format("2006-01-02 15:04:05"),
		boolToInt(p.Encrypted), boolToInt(p.BurnAfterRead),
		nullIfEmpty(p.SessionID), nullIfEmpty(p.APIKeyID), nullIfEmpty(p.DeleteTokenHash),
		0,
	)
	return err
}

func (s *SQLiteStore) Get(ctx context.Context, id string) (*Paste, error) {
	var p Paste
	var expiresAt, createdAt, sessionID, apiKeyID, deleteTokenHash sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, type, filename, content_type, size, title, syntax, visibility, expires_at, created_at, encrypted, burn_after_read, session_id, api_key_id, delete_token_hash, COALESCE(view_count, 0)
		FROM pastes WHERE id = ?
	`, id).Scan(
		&p.ID, &p.Type, &p.Filename, &p.ContentType, &p.Size, &p.Title, &p.Syntax, &p.Visibility,
		&expiresAt, &createdAt,
		&p.Encrypted, &p.BurnAfterRead,
		&sessionID, &apiKeyID, &deleteTokenHash,
		&p.ViewCount,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if expiresAt.Valid {
		t, _ := time.Parse("2006-01-02 15:04:05", expiresAt.String)
		p.ExpiresAt = &t
	}
	if createdAt.Valid {
		t, _ := time.Parse("2006-01-02 15:04:05", createdAt.String)
		p.CreatedAt = t
	}
	p.SessionID = sessionID.String
	p.APIKeyID = apiKeyID.String
	p.DeleteTokenHash = deleteTokenHash.String
	return &p, nil
}

func (s *SQLiteStore) Exists(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT 1 FROM pastes WHERE id = ? LIMIT 1", id).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteStore) CreateAPIKey(ctx context.Context, id, keyHash string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO api_keys (id, key_hash) VALUES (?, ?)", id, keyHash)
	return err
}

func (s *SQLiteStore) GetAPIKeyID(ctx context.Context, keyHash string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, "SELECT id FROM api_keys WHERE key_hash = ?", keyHash).Scan(&id)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return id, err
}

func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	r, err := s.db.ExecContext(ctx, "DELETE FROM pastes WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) ListBySession(ctx context.Context, sessionID string, limit, offset int) ([]*PasteMeta, error) {
	return s.list(ctx, "session_id = ?", sessionID, limit, offset)
}

func (s *SQLiteStore) ListByAPIKey(ctx context.Context, apiKeyID string, limit, offset int) ([]*PasteMeta, error) {
	return s.list(ctx, "api_key_id = ?", apiKeyID, limit, offset)
}

func (s *SQLiteStore) ListRecent(ctx context.Context, limit, offset int) ([]*PasteMeta, error) {
	where := "visibility = 'public' AND (expires_at IS NULL OR expires_at > datetime('now'))"
	return s.listWhere(ctx, where, nil, limit, offset)
}

func (s *SQLiteStore) list(ctx context.Context, where string, arg interface{}, limit, offset int) ([]*PasteMeta, error) {
	return s.listWhere(ctx, where+" AND (expires_at IS NULL OR expires_at > datetime('now'))", arg, limit, offset)
}

func (s *SQLiteStore) listWhere(ctx context.Context, where string, arg interface{}, limit, offset int) ([]*PasteMeta, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `SELECT id, type, filename, content_type, size, title, syntax, created_at, expires_at, COALESCE(view_count, 0)
		FROM pastes WHERE ` + where + `
		ORDER BY created_at DESC LIMIT ? OFFSET ?`
	var rows *sql.Rows
	var err error
	if arg != nil {
		rows, err = s.db.QueryContext(ctx, query, arg, limit, offset)
	} else {
		rows, err = s.db.QueryContext(ctx, query, limit, offset)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*PasteMeta
	for rows.Next() {
		var m PasteMeta
		var expiresAt, createdAt sql.NullString
		err := rows.Scan(&m.ID, &m.Type, &m.Filename, &m.ContentType, &m.Size, &m.Title, &m.Syntax, &createdAt, &expiresAt, &m.ViewCount)
		if err != nil {
			return nil, err
		}
		if createdAt.Valid {
			t, _ := time.Parse("2006-01-02 15:04:05", createdAt.String)
			m.CreatedAt = t
		}
		if expiresAt.Valid {
			t, _ := time.Parse("2006-01-02 15:04:05", expiresAt.String)
			m.ExpiresAt = &t
		}
		list = append(list, &m)
	}
	return list, rows.Err()
}

func (s *SQLiteStore) Stats(ctx context.Context) (*Stats, error) {
	var st Stats
	err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM pastes) AS total_pastes,
			(SELECT COUNT(*) FROM pastes WHERE type = 'text') AS total_text,
			(SELECT COUNT(*) FROM pastes WHERE type = 'file') AS total_files,
			(SELECT COALESCE(SUM(size), 0) FROM pastes) AS total_size,
			(SELECT COALESCE(SUM(COALESCE(view_count, 0)), 0) FROM pastes) AS total_views,
			(SELECT COUNT(*) FROM api_keys) AS api_keys_count,
			(SELECT COUNT(*) FROM pastes WHERE created_at >= datetime('now', '-1 day')) AS pastes_last_24h,
			(SELECT COUNT(*) FROM pastes WHERE created_at >= datetime('now', '-7 days')) AS pastes_last_7d
	`).Scan(
		&st.TotalPastes, &st.TotalText, &st.TotalFiles,
		&st.TotalSize, &st.TotalViews, &st.APIKeysCount,
		&st.PastesLast24h, &st.PastesLast7d,
	)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *SQLiteStore) IncrementViewCount(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE pastes SET view_count = COALESCE(view_count, 0) + 1 WHERE id = ?", id)
	return err
}

func (s *SQLiteStore) ListExpired(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id FROM pastes WHERE expires_at IS NOT NULL AND expires_at < datetime('now') LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
