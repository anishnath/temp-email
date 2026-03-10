package pastebin

import (
	"context"
	"os"
	"path/filepath"
)

const fsKeyPrefix = "pastes/"

// FSStore implements ContentStore using local filesystem.
type FSStore struct {
	baseDir string
}

// NewFSStore creates a filesystem content store.
func NewFSStore(baseDir string) (*FSStore, error) {
	if baseDir == "" {
		baseDir = "/tmp/pastebin-content"
	}
	if err := os.MkdirAll(filepath.Join(baseDir, fsKeyPrefix), 0750); err != nil {
		return nil, err
	}
	return &FSStore{baseDir: baseDir}, nil
}

func (s *FSStore) key(id string) string {
	return filepath.Join(s.baseDir, fsKeyPrefix, id)
}

func (s *FSStore) Put(ctx context.Context, key string, data []byte, contentType string) error {
	p := s.key(key)
	return os.WriteFile(p, data, 0640)
}

func (s *FSStore) Get(ctx context.Context, key string) ([]byte, string, error) {
	p := s.key(key)
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", ErrNotFound
		}
		return nil, "", err
	}
	return data, "", nil
}

func (s *FSStore) Delete(ctx context.Context, key string) error {
	p := s.key(key)
	err := os.Remove(p)
	if err != nil && os.IsNotExist(err) {
		return ErrNotFound
	}
	return err
}
