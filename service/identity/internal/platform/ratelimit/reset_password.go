package ratelimit

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	appresetpassword "github.com/DoMinhHHung/beexster/service/identity/internal/application/resetpassword"
)

type ResetPasswordPolicy struct {
	IPLimit  int64
	IPWindow time.Duration
}

type ResetPasswordLimiter struct {
	limiter *SlidingWindow
	keys    *KeyBuilder
	policy  ResetPasswordPolicy
}

func NewResetPasswordLimiter(
	limiter *SlidingWindow,
	keys *KeyBuilder,
	policy ResetPasswordPolicy,
) (*ResetPasswordLimiter, error) {
	if limiter == nil || keys == nil {
		return nil, ErrNotInitialized
	}
	if policy.IPLimit <= 0 {
		return nil, ErrInvalidLimit
	}
	if policy.IPWindow <= 0 {
		return nil, ErrInvalidWindow
	}

	return &ResetPasswordLimiter{
		limiter: limiter,
		keys:    keys,
		policy:  policy,
	}, nil
}

func (l *ResetPasswordLimiter) AllowResetPasswordIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}

	key, err := l.keys.ForIP(ActionResetPassword, ipAddress)
	if err != nil {
		return false, fmt.Errorf(
			"build reset-password IP rate-limit key: %w",
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
			"check reset-password IP rate limit: %w",
			err,
		)
	}

	return result.Allowed, nil
}

var _ appresetpassword.RateLimiter = (*ResetPasswordLimiter)(nil)
