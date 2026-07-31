package ratelimit

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestLoginLimiterUsesIndependentIPAndEmailPolicies(t *testing.T) {
	t.Parallel()

	_, _, slidingWindow := newTestLimiter(t)

	keys, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}

	limiter, err := NewLoginLimiter(
		slidingWindow,
		keys,
		LoginPolicy{
			IPLimit:     2,
			IPWindow:    time.Minute,
			EmailLimit:  1,
			EmailWindow: time.Minute,
		},
	)
	if err != nil {
		t.Fatalf("create login limiter: %v", err)
	}

	ipAddress := netip.MustParseAddr("192.0.2.10")

	allowed, err := limiter.AllowLoginIP(
		context.Background(),
		"request-1",
		ipAddress,
	)
	if err != nil || !allowed {
		t.Fatalf("expected first IP request allowed, allowed=%t err=%v", allowed, err)
	}

	allowed, err = limiter.AllowLoginEmail(
		context.Background(),
		"request-1",
		"User@Example.COM",
	)
	if err != nil || !allowed {
		t.Fatalf("expected first email request allowed, allowed=%t err=%v", allowed, err)
	}

	allowed, err = limiter.AllowLoginEmail(
		context.Background(),
		"request-2",
		"user@example.com",
	)
	if err != nil {
		t.Fatalf("check second email request: %v", err)
	}

	if allowed {
		t.Fatal("expected normalized email limit to reject second request")
	}
}
