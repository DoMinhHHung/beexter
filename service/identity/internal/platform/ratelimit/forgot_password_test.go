package ratelimit

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestForgotPasswordLimiterSharesOneActionBucket(t *testing.T) {
	t.Parallel()

	_, _, slidingWindow := newTestLimiter(t)
	keys, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}

	limiter, err := NewForgotPasswordLimiter(
		slidingWindow,
		keys,
		ForgotPasswordPolicy{
			IPLimit:     10,
			IPWindow:    time.Minute,
			EmailLimit:  1,
			EmailWindow: time.Hour,
		},
	)
	if err != nil {
		t.Fatalf("create forgot-password limiter: %v", err)
	}

	allowed, err := limiter.AllowForgotPasswordEmail(
		context.Background(),
		"request-1",
		"User@Example.COM",
	)
	if err != nil {
		t.Fatalf("check first request: %v", err)
	}
	if !allowed {
		t.Fatal("expected first request to be allowed")
	}

	allowed, err = limiter.AllowForgotPasswordEmail(
		context.Background(),
		"request-2",
		"user@example.com",
	)
	if err != nil {
		t.Fatalf("check second request: %v", err)
	}
	if allowed {
		t.Fatal("expected normalized duplicate email to be rejected")
	}
}

func TestForgotPasswordLimiterEnforcesIPPolicy(t *testing.T) {
	t.Parallel()

	_, _, slidingWindow := newTestLimiter(t)
	keys, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}

	limiter, err := NewForgotPasswordLimiter(
		slidingWindow,
		keys,
		ForgotPasswordPolicy{
			IPLimit:     1,
			IPWindow:    time.Minute,
			EmailLimit:  10,
			EmailWindow: time.Hour,
		},
	)
	if err != nil {
		t.Fatalf("create forgot-password limiter: %v", err)
	}

	ipAddress := netip.MustParseAddr("192.0.2.10")
	allowed, err := limiter.AllowForgotPasswordIP(
		context.Background(),
		"request-1",
		ipAddress,
	)
	if err != nil {
		t.Fatalf("check first request: %v", err)
	}
	if !allowed {
		t.Fatal("expected first request to be allowed")
	}

	allowed, err = limiter.AllowForgotPasswordIP(
		context.Background(),
		"request-2",
		ipAddress,
	)
	if err != nil {
		t.Fatalf("check second request: %v", err)
	}
	if allowed {
		t.Fatal("expected second request to be rejected")
	}
}
