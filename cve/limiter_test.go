package cve

import (
	"context"
	"testing"
	"time"
)

func TestLimiterReserve(t *testing.T) {
	l := newLimiter(2, time.Minute)
	now := time.Unix(1000, 0)

	if d := l.reserve(now); d != 0 {
		t.Fatalf("first send delayed by %v", d)
	}
	if d := l.reserve(now.Add(time.Second)); d != 0 {
		t.Fatalf("second send delayed by %v", d)
	}
	if d := l.reserve(now.Add(2 * time.Second)); d != 58*time.Second {
		t.Fatalf("third send delayed by %v, want 58s", d)
	}
	if d := l.reserve(now.Add(61 * time.Second)); d != 0 {
		t.Fatalf("send after window delayed by %v", d)
	}
}

func TestLimiterWaitHonoursContext(t *testing.T) {
	l := newLimiter(1, time.Hour)
	if err := l.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := l.wait(ctx); err == nil {
		t.Fatal("wait returned before context expired")
	}
}
