package ratelimit

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	appchangepassword "github.com/DoMinhHHung/beexster/service/identity/internal/application/changepassword"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

type ChangePasswordPolicy struct {
	IPLimit        int64
	IPWindow       time.Duration
	IdentityLimit  int64
	IdentityWindow time.Duration
}

type ChangePasswordLimiter struct {
	limiter *SlidingWindow
	keys    *KeyBuilder
	policy  ChangePasswordPolicy
}

func NewChangePasswordLimiter(
	limiter *SlidingWindow,
	keys *KeyBuilder,
	policy ChangePasswordPolicy,
) (*ChangePasswordLimiter, error) {
	if limiter == nil || keys == nil {
		return nil, ErrNotInitialized
	}
	if policy.IPLimit <= 0 || policy.IdentityLimit <= 0 {
		return nil, ErrInvalidLimit
	}
	if policy.IPWindow <= 0 || policy.IdentityWindow <= 0 {
		return nil, ErrInvalidWindow
	}

	return &ChangePasswordLimiter{
		limiter: limiter,
		keys:    keys,
		policy:  policy,
	}, nil
}

func (l *ChangePasswordLimiter) AllowChangePasswordIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}

	key, err := l.keys.ForIP(ActionChangePassword, ipAddress)
	if err != nil {
		return false, fmt.Errorf(
			"build change-password IP rate-limit key: %w",
			err,
		)
	}

	result, err := l.limiter.Allow(
		ctx,
		key,
		requestID,
		l.policy.IPLimit,
		l.policy.IPWindow,
	)
	if err != nil {
		return false, fmt.Errorf(
			"check change-password IP rate limit: %w",
			err,
		)
	}

	return result.Allowed, nil
}

func (l *ChangePasswordLimiter) AllowChangePasswordIdentity(
	ctx context.Context,
	requestID string,
	identityID identity.ID,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}

	key, err := l.keys.ForIdentity(ActionChangePassword, identityID)
	if err != nil {
		return false, fmt.Errorf(
			"build change-password identity rate-limit key: %w",
			err,
		)
	}

	result, err := l.limiter.Allow(
		ctx,
		key,
		requestID,
		l.policy.IdentityLimit,
		l.policy.IdentityWindow,
	)
	if err != nil {
		return false, fmt.Errorf(
			"check change-password identity rate limit: %w",
			err,
		)
	}

	return result.Allowed, nil
}

var _ appchangepassword.RateLimiter = (*ChangePasswordLimiter)(nil)
