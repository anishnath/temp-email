package pastebin

import (
	"regexp"
	"strings"
)

// Blocklist checks content against banned patterns.
type Blocklist struct {
	words []string
	regex []*regexp.Regexp
}

// NewBlocklist parses PASTEBIN_BLOCKLIST (comma-separated words or regex).
func NewBlocklist(s string) *Blocklist {
	b := &Blocklist{}
	if s == "" {
		return b
	}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") {
			re, err := regexp.Compile("(?i)" + p[1:len(p)-1])
			if err == nil {
				b.regex = append(b.regex, re)
			}
			continue
		}
		b.words = append(b.words, strings.ToLower(p))
	}
	return b
}

// Blocked returns true if content matches any blocked pattern.
func (b *Blocklist) Blocked(content string) bool {
	lower := strings.ToLower(content)
	for _, w := range b.words {
		if strings.Contains(lower, w) {
			return true
		}
	}
	for _, re := range b.regex {
		if re.MatchString(content) {
			return true
		}
	}
	return false
}
