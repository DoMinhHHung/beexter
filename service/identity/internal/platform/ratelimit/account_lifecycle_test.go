package ratelimit

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const lifecycleRateLimitUserID = identity.ID(
	"0198f124-659f-7cbd-a441-dc7eea175073",
)

func TestDeleteAccountLimiterEnforcesIdentityPolicy(t *testing.T) {
	t.Parallel()

	_, _, slidingWindow := newTestLimiter(t)
	keys, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}

	limiter, err := NewDeleteAccountLimiter(
		slidingWindow,
		keys,
		DeleteAccountPolicy{
			IPLimit:        10,
			IPWindow:       time.Minute,
			IdentityLimit:  1,
			IdentityWindow: time.Hour,
		},
	)
	if err != nil {
		t.Fatalf("create delete-account limiter: %v", err)
	}

	allowed, err := limiter.AllowDeleteAccountIdentity(
		context.Background(),
		"request-1",
		lifecycleRateLimitUserID,
	)
	if err != nil || !allowed {
		t.Fatalf("expected first request allowed, allowed=%v err=%v", allowed, err)
	}
	allowed, err = limiter.AllowDeleteAccountIdentity(
		context.Background(),
		"request-2",
		lifecycleRateLimitUserID,
	)
	if err != nil || allowed {
		t.Fatalf("expected second request rejected, allowed=%v err=%v", allowed, err)
	}
}

func TestReactivationLimiterNormalizesEmail(t *testing.T) {
	t.Parallel()

	_, _, slidingWindow := newTestLimiter(t)
	keys, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}

	limiter, err := NewReactivationLimiter(
		slidingWindow,
		keys,
		ReactivationPolicy{
			IPLimit:     10,
			IPWindow:    time.Minute,
			EmailLimit:  1,
			EmailWindow: time.Hour,
		},
	)
	if err != nil {
		t.Fatalf("create reactivation limiter: %v", err)
	}

	allowed, err := limiter.AllowReactivationEmail(
		context.Background(),
		"request-1",
		"User@Example.COM",
	)
	if err != nil || !allowed {
		t.Fatalf("expected first request allowed, allowed=%v err=%v", allowed, err)
	}
	allowed, err = limiter.AllowReactivationEmail(
		context.Background(),
		"request-2",
		"user@example.com",
	)
	if err != nil || allowed {
		t.Fatalf("expected normalized duplicate rejected, allowed=%v err=%v", allowed, err)
	}
}

func TestDeleteAccountLimiterEnforcesIPPolicy(t *testing.T) {
	t.Parallel()

	_, _, slidingWindow := newTestLimiter(t)
	keys, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}
	limiter, err := NewDeleteAccountLimiter(
		slidingWindow,
		keys,
		DeleteAccountPolicy{
			IPLimit:        1,
			IPWindow:       time.Minute,
			IdentityLimit:  10,
			IdentityWindow: time.Hour,
		},
	)
	if err != nil {
		t.Fatalf("create delete-account limiter: %v", err)
	}
	ipAddress := netip.MustParseAddr("192.0.2.10")
	allowed, err := limiter.AllowDeleteAccountIP(
		context.Background(),
		"request-1",
		ipAddress,
	)
	if err != nil || !allowed {
		t.Fatalf("expected first request allowed, allowed=%v err=%v", allowed, err)
	}
	allowed, err = limiter.AllowDeleteAccountIP(
		context.Background(),
		"request-2",
		ipAddress,
	)
	if err != nil || allowed {
		t.Fatalf("expected second request rejected, allowed=%v err=%v", allowed, err)
	}
}
