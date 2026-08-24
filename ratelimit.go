package gw

import (
	"sync"
	"time"
)

// TokenBucket is a token bucket rate limiter with dynamic parameter adjustment.
type TokenBucket struct {
	mu         sync.Mutex
	rate       float64
	burst      int64
	tokens     float64
	lastRefill time.Time
}

// NewTokenBucket creates a token bucket rate limiter.
func NewTokenBucket(rate float64, burst int64) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastRefill: time.Now(),
	}
}

func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	if elapsed > 0 {
		tb.tokens += elapsed * tb.rate
		if tb.tokens > float64(tb.burst) {
			tb.tokens = float64(tb.burst)
		}
		tb.lastRefill = now
	}
}

// Allow checks whether n tokens can be consumed (non-blocking).
func (tb *TokenBucket) Allow(n int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	if tb.tokens >= float64(n) {
		tb.tokens -= float64(n)
		return true
	}
	return false
}

// WaitN blocks until enough tokens are available.
func (tb *TokenBucket) WaitN(n int) {
	for {
		tb.mu.Lock()
		// rate <= 0 means unlimited: never block.
		if tb.rate <= 0 {
			tb.mu.Unlock()
			return
		}
		tb.refill()
		if tb.tokens >= float64(n) {
			tb.tokens -= float64(n)
			tb.mu.Unlock()
			return
		}
		waitTokens := float64(n) - tb.tokens
		waitDuration := time.Duration((waitTokens / tb.rate) * float64(time.Second))
		tb.mu.Unlock()

		if waitDuration > 100*time.Millisecond {
			waitDuration = 100 * time.Millisecond
		}
		if waitDuration < time.Microsecond {
			waitDuration = time.Microsecond
		}
		time.Sleep(waitDuration)
	}
}

// SetRate sets the token refill rate.
func (tb *TokenBucket) SetRate(rate float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.rate = rate
}

// SetBurst sets the token bucket capacity.
func (tb *TokenBucket) SetBurst(burst int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.burst = burst
	if tb.tokens > float64(burst) {
		tb.tokens = float64(burst)
	}
}
