package cve

import (
	"context"
	"sync"
	"time"
)

// limiter allows at most max sends per sliding window.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	sent   []time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window}
}

// wait blocks until a send is within budget, then records it.
func (l *limiter) wait(ctx context.Context) error {
	for {
		delay := l.reserve(time.Now())
		if delay == 0 {
			return nil
		}
		if err := sleep(ctx, delay); err != nil {
			return err
		}
	}
}

// reserve records a send at now when the budget allows; otherwise it returns how long
// to wait before the oldest send leaves the window.
func (l *limiter) reserve(now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	kept := l.sent[:0]
	for _, t := range l.sent {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.sent = kept
	if len(l.sent) < l.max {
		l.sent = append(l.sent, now)
		return 0
	}
	return l.sent[0].Sub(cutoff)
}

// sleep waits for d unless ctx ends first.
func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
