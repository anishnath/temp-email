package arduino

import (
	"os"
	"strconv"
	"sync"
	"time"
)

// RateLimiter tracks per-IP active QEMU sessions and enforces limits.
//
// Environment:
//
//	QEMU_MAX_PER_IP       — max concurrent instances per IP (default: 2)
//	QEMU_COOLDOWN_SEC     — minimum seconds between starts from same IP (default: 10)
type RateLimiter struct {
	MaxPerIP   int
	CooldownMs int64

	mu      sync.Mutex
	active  map[string]int       // IP → active instance count
	lastUse map[string]time.Time // IP → last start time
}

// NewRateLimiter creates a rate limiter from env config.
func NewRateLimiter() *RateLimiter {
	maxPerIP := 2
	if v := os.Getenv("QEMU_MAX_PER_IP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxPerIP = n
		}
	}
	cooldown := int64(10000) // 10 seconds in ms
	if v := os.Getenv("QEMU_COOLDOWN_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cooldown = int64(n) * 1000
		}
	}
	return &RateLimiter{
		MaxPerIP:   maxPerIP,
		CooldownMs: cooldown,
		active:     make(map[string]int),
		lastUse:    make(map[string]time.Time),
	}
}

// Allow checks if an IP can start a new instance.
// Returns ("", true) if allowed, or (reason, false) if denied.
func (rl *RateLimiter) Allow(ip string) (string, bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check cooldown
	if last, ok := rl.lastUse[ip]; ok {
		elapsed := time.Since(last).Milliseconds()
		if elapsed < rl.CooldownMs {
			remaining := (rl.CooldownMs - elapsed) / 1000
			return "please wait " + strconv.FormatInt(remaining+1, 10) + "s before starting another simulation", false
		}
	}

	// Check per-IP limit
	if rl.active[ip] >= rl.MaxPerIP {
		return "max " + strconv.Itoa(rl.MaxPerIP) + " concurrent simulations per IP", false
	}

	return "", true
}

// Acquire marks a new instance for an IP. Call Release when it stops.
func (rl *RateLimiter) Acquire(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.active[ip]++
	rl.lastUse[ip] = time.Now()
}

// Release decrements the active count for an IP.
func (rl *RateLimiter) Release(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.active[ip] > 0 {
		rl.active[ip]--
	}
	if rl.active[ip] == 0 {
		delete(rl.active, ip)
	}
}

// ActiveCount returns the number of active instances for an IP.
func (rl *RateLimiter) ActiveCount(ip string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.active[ip]
}
