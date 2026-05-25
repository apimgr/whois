package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Limiter implements sliding window rate limiting
type Limiter struct {
	mu           sync.RWMutex
	windows      map[string]*window
	requests     int
	duration     time.Duration
	cleanupInt   time.Duration
	stopChan     chan struct{}
}

// window represents a sliding window for rate limiting
type window struct {
	requests   int
	windowTime time.Time
}

// New creates a new rate limiter
func New(requests int, duration time.Duration) *Limiter {
	if requests <= 0 {
		requests = 60
	}
	if duration <= 0 {
		duration = 1 * time.Minute
	}

	l := &Limiter{
		windows:    make(map[string]*window),
		requests:   requests,
		duration:   duration,
		cleanupInt: 1 * time.Minute,
		stopChan:   make(chan struct{}),
	}

	go l.cleanupLoop()

	return l
}

// Allow checks if a request is allowed for the given key
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	w, exists := l.windows[key]

	if !exists {
		l.windows[key] = &window{
			requests:   1,
			windowTime: now,
		}
		return true
	}

	elapsed := now.Sub(w.windowTime)
	if elapsed >= l.duration {
		l.windows[key] = &window{
			requests:   1,
			windowTime: now,
		}
		return true
	}

	if w.requests >= l.requests {
		return false
	}

	w.requests++
	return true
}

// GetKey extracts rate limit key from request
func (l *Limiter) GetKey(r *http.Request) string {
	return GetClientIP(r)
}

// Close stops the cleanup loop
func (l *Limiter) Close() {
	close(l.stopChan)
}

// cleanupLoop periodically removes old windows
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(l.cleanupInt)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.cleanupExpired()
		case <-l.stopChan:
			return
		}
	}
}

// cleanupExpired removes expired windows
func (l *Limiter) cleanupExpired() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for key, w := range l.windows {
		if now.Sub(w.windowTime) > l.duration*2 {
			delete(l.windows, key)
		}
	}
}

// GetClientIP extracts the client IP address from request
func GetClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := parseXForwardedFor(xff)
		if len(ips) > 0 {
			return ips[0]
		}
	}

	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// parseXForwardedFor parses X-Forwarded-For header
func parseXForwardedFor(header string) []string {
	var ips []string
	for i := 0; i < len(header); {
		start := i
		for i < len(header) && header[i] != ',' {
			i++
		}

		ip := header[start:i]
		for j := 0; j < len(ip); j++ {
			if ip[j] != ' ' && ip[j] != '\t' {
				ip = ip[j:]
				break
			}
		}
		for j := len(ip) - 1; j >= 0; j-- {
			if ip[j] != ' ' && ip[j] != '\t' {
				ip = ip[:j+1]
				break
			}
		}

		if len(ip) > 0 {
			ips = append(ips, ip)
		}

		if i < len(header) {
			i++
		}
	}
	return ips
}

// Stats returns rate limiter statistics
type Stats struct {
	TotalKeys   int           `json:"total_keys"`
	Requests    int           `json:"requests_limit"`
	Duration    time.Duration `json:"duration"`
	WindowCount int           `json:"window_count"`
}

// Stats returns current rate limiter statistics
func (l *Limiter) Stats() *Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return &Stats{
		TotalKeys:   len(l.windows),
		Requests:    l.requests,
		Duration:    l.duration,
		WindowCount: len(l.windows),
	}
}
