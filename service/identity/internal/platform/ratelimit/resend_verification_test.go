package ratelimit

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestResendVerificationLimiterEnforcesIPPolicy(
	t *testing.T,
) {
	t.Parallel()

	_, _, slidingWindow := newTestLimiter(t)

	keys, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf(
			"create key builder: %v",
			err,
		)
	}

	limiter, err := NewResendVerificationLimiter(
		slidingWindow,
		keys,
		ResendVerificationPolicy{
			IPLimit:     1,
			IPWindow:    time.Minute,
			EmailLimit:  2,
			EmailWindow: time.Hour,
		},
	)
	if err != nil {
		t.Fatalf(
			"create resend-verification limiter: %v",
			err,
		)
	}

	ipAddress := netip.MustParseAddr(
		"192.0.2.10",
	)

	allowed, err :=
		limiter.AllowResendVerificationIP(
			context.Background(),
			"request-1",
			ipAddress,
		)
	if err != nil {
		t.Fatalf(
			"check first IP request: %v",
			err,
		)
	}

	if !allowed {
		t.Fatal(
			"expected first IP request to be allowed",
		)
	}

	allowed, err =
		limiter.AllowResendVerificationIP(
			context.Background(),
			"request-2",
			ipAddress,
		)
	if err != nil {
		t.Fatalf(
			"check second IP request: %v",
			err,
		)
	}

	if allowed {
		t.Fatal(
			"expected second IP request to be rejected",
		)
	}
}

func TestResendVerificationLimiterEnforcesEmailPolicy(
	t *testing.T,
) {
	t.Parallel()

	_, _, slidingWindow := newTestLimiter(t)

	keys, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf(
			"create key builder: %v",
			err,
		)
	}

	limiter, err := NewResendVerificationLimiter(
		slidingWindow,
		keys,
		ResendVerificationPolicy{
			IPLimit:     10,
			IPWindow:    time.Minute,
			EmailLimit:  1,
			EmailWindow: time.Hour,
		},
	)
	if err != nil {
		t.Fatalf(
			"create resend-verification limiter: %v",
			err,
		)
	}

	allowed, err :=
		limiter.AllowResendVerificationEmail(
			context.Background(),
			"request-1",
			"User@Example.COM",
		)
	if err != nil {
		t.Fatalf(
			"check first email request: %v",
			err,
		)
	}

	if !allowed {
		t.Fatal(
			"expected first email request to be allowed",
		)
	}

	allowed, err =
		limiter.AllowResendVerificationEmail(
			context.Background(),
			"request-2",
			"user@example.com",
		)
	if err != nil {
		t.Fatalf(
			"check second email request: %v",
			err,
		)
	}

	if allowed {
		t.Fatal(
			"expected normalized duplicate email to be rejected",
		)
	}
}
