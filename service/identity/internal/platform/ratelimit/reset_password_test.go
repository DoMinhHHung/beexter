package ratelimit

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestResetPasswordLimiterEnforcesIPPolicy(t *testing.T) {
	t.Parallel()

	_, _, slidingWindow := newTestLimiter(t)

	keys, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}

	limiter, err := NewResetPasswordLimiter(
		slidingWindow,
		keys,
		ResetPasswordPolicy{
			IPLimit:  1,
			IPWindow: time.Minute,
		},
	)
	if err != nil {
		t.Fatalf("create reset-password limiter: %v", err)
	}

	ipAddress := netip.MustParseAddr("192.0.2.10")

	allowed, err := limiter.AllowResetPasswordIP(
		context.Background(),
		"request-1",
		ipAddress,
	)
	if err != nil {
		t.Fatalf("check first reset-password request: %v", err)
	}
	if !allowed {
		t.Fatal("expected first reset-password request to be allowed")
	}

	allowed, err = limiter.AllowResetPasswordIP(
		context.Background(),
		"request-2",
		ipAddress,
	)
	if err != nil {
		t.Fatalf("check second reset-password request: %v", err)
	}
	if allowed {
		t.Fatal("expected second reset-password request to be rejected")
	}
}
