package ratelimit

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

const changePasswordRateLimitUserID = identity.ID(
	"0198f124-659f-7cbd-a441-dc7eea175073",
)

func TestChangePasswordLimiterEnforcesIPAndIdentityPolicies(t *testing.T) {
	t.Parallel()

	_, _, slidingWindow := newTestLimiter(t)
	keys, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}

	limiter, err := NewChangePasswordLimiter(
		slidingWindow,
		keys,
		ChangePasswordPolicy{
			IPLimit:        1,
			IPWindow:       time.Minute,
			IdentityLimit:  1,
			IdentityWindow: time.Minute,
		},
	)
	if err != nil {
		t.Fatalf("create limiter: %v", err)
	}

	ipAddress := netip.MustParseAddr("192.0.2.10")
	allowed, err := limiter.AllowChangePasswordIP(
		context.Background(),
		"request-1",
		ipAddress,
	)
	if err != nil || !allowed {
		t.Fatalf("expected first IP request allowed, allowed=%v err=%v", allowed, err)
	}
	allowed, err = limiter.AllowChangePasswordIP(
		context.Background(),
		"request-2",
		ipAddress,
	)
	if err != nil || allowed {
		t.Fatalf("expected second IP request rejected, allowed=%v err=%v", allowed, err)
	}

	allowed, err = limiter.AllowChangePasswordIdentity(
		context.Background(),
		"request-1",
		changePasswordRateLimitUserID,
	)
	if err != nil || !allowed {
		t.Fatalf("expected first identity request allowed, allowed=%v err=%v", allowed, err)
	}
	allowed, err = limiter.AllowChangePasswordIdentity(
		context.Background(),
		"request-2",
		changePasswordRateLimitUserID,
	)
	if err != nil || allowed {
		t.Fatalf("expected second identity request rejected, allowed=%v err=%v", allowed, err)
	}
}

func TestKeyBuilderHashesIdentitySubject(t *testing.T) {
	t.Parallel()

	keys, err := NewKeyBuilder(testKeySecret)
	if err != nil {
		t.Fatalf("create key builder: %v", err)
	}

	key, err := keys.ForIdentity(
		ActionChangePassword,
		changePasswordRateLimitUserID,
	)
	if err != nil {
		t.Fatalf("build identity key: %v", err)
	}
	if strings.Contains(key, changePasswordRateLimitUserID.String()) {
		t.Fatalf("identity ID must not appear raw in rate-limit key: %q", key)
	}
}
