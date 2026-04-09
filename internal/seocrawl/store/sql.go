package store

import (
	"crypto/sha256"
	"encoding/hex"
)

const paginationMax = 25

// Hash returns a SHA-256 hex digest of s (same as SEOnaut repository).
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Truncate shortens s to length runes, appending "..." when trimmed.
func Truncate(s string, length int) string {
	text := []rune(s)
	if len(text) > length {
		s = string(text[:length-3]) + "..."
	}
	return s
}
