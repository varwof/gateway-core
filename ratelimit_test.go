package gw

import (
	"sync"
	"testing"
	"time"
)

func TestTokenBucketAllow(t *testing.T) {
	tb := NewTokenBucket(100, 10)
	if !tb.Allow(5) {
		t.Error("expected Allow(5) true with burst=10")
	}
	if !tb.Allow(5) {
		t.Error("expected Allow(5) true (second call)")
	}
	if tb.Allow(5) {
		t.Error("expected Allow(5) false (exceeded burst)")
	}
}

func TestTokenBucketRefill(t *testing.T) {
	tb := NewTokenBucket(1000, 100)
	if !tb.Allow(100) {
		t.Error("expected Allow(100) true with burst=100")
	}
	time.Sleep(200 * time.Millisecond)
	if !tb.Allow(100) {
		t.Error("expected Allow(100) true after refill")
	}
}

func TestTokenBucketConcurrent(t *testing.T) {
	tb := NewTokenBucket(1e9, 1e9)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !tb.Allow(100) {
				t.Error("concurrent Allow failed")
			}
		}()
	}
	wg.Wait()
}

func TestTokenBucketSetRate(t *testing.T) {
	tb := NewTokenBucket(1000, 100)
	tb.Allow(100)
	tb.SetRate(1000)
	time.Sleep(500 * time.Millisecond)
	if !tb.Allow(100) {
		t.Fatal("expected Allow(100) true after 0.5s at 1000Bps refill")
	}
}

func TestTokenBucketHighRate(t *testing.T) {
	tb := NewTokenBucket(1e9, 1e9)
	start := time.Now()
	for i := 0; i < 100; i++ {
		if !tb.Allow(1000000) {
			t.Fatalf("Allow(1000000) failed at iteration %d after %v", i, time.Since(start))
		}
	}
}

func TestTokenBucketSetBurst(t *testing.T) {
	tb := NewTokenBucket(1000, 10)
	tb.Allow(10)
	tb.SetBurst(100)
	time.Sleep(100 * time.Millisecond)
	if !tb.Allow(50) {
		t.Error("expected Allow(50) true after burst increase + refill")
	}
}

func TestTokenBucketWaitN(t *testing.T) {
	tb := NewTokenBucket(1000, 100)
	start := time.Now()
	tb.WaitN(100)
	elapsed := time.Since(start)
	if elapsed > 50*time.Millisecond {
		t.Errorf("WaitN(100) took %v, expected instant", elapsed)
	}
}

func TestTokenBucketZeroRate(t *testing.T) {
	tb := NewTokenBucket(0, 1)
	tb.Allow(1)
	if tb.Allow(1) {
		t.Error("expected Allow(1) false after exhausting burst with zero rate")
	}
}

// H3: WaitN must return immediately when rate <= 0 (unlimited), otherwise it
// would spin forever waiting for tokens that never refill.
func TestTokenBucketWaitNZeroRate(t *testing.T) {
	tb := NewTokenBucket(0, 1)
	start := time.Now()
	tb.WaitN(1)
	tb.WaitN(1000)
	elapsed := time.Since(start)
	if elapsed > 50*time.Millisecond {
		t.Errorf("WaitN with zero rate took %v, expected instant (no deadlock)", elapsed)
	}
}
