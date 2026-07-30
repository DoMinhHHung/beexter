package ratelimit

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	appresendverification "github.com/DoMinhHHung/beexter/service/identity/internal/application/resendverification"
)

type ResendVerificationPolicy struct {
	IPLimit     int64
	IPWindow    time.Duration
	EmailLimit  int64
	EmailWindow time.Duration
}

type ResendVerificationLimiter struct {
	limiter *SlidingWindow
	keys    *KeyBuilder
	policy  ResendVerificationPolicy
}

func NewResendVerificationLimiter(
	limiter *SlidingWindow,
	keys *KeyBuilder,
	policy ResendVerificationPolicy,
) (*ResendVerificationLimiter, error) {
	if limiter == nil || keys == nil {
		return nil, ErrNotInitialized
	}

	if policy.IPLimit <= 0 ||
		policy.EmailLimit <= 0 {
		return nil, ErrInvalidLimit
	}

	if policy.IPWindow <= 0 ||
		policy.EmailWindow <= 0 {
		return nil, ErrInvalidWindow
	}

	return &ResendVerificationLimiter{
		limiter: limiter,
		keys:    keys,
		policy:  policy,
	}, nil
}

func (l *ResendVerificationLimiter) AllowResendVerificationIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	if l == nil ||
		l.limiter == nil ||
		l.keys == nil {
		return false, ErrNotInitialized
	}

	key, err := l.keys.ForIP(
		ActionResendVerification,
		ipAddress,
	)
	if err != nil {
		return false, fmt.Errorf(
			"build resend-verification IP rate-limit key: %w",
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
			"check resend-verification IP rate limit: %w",
			err,
		)
	}

	return result.Allowed, nil
}

func (l *ResendVerificationLimiter) AllowResendVerificationEmail(
	ctx context.Context,
	requestID string,
	email string,
) (bool, error) {
	if l == nil ||
		l.limiter == nil ||
		l.keys == nil {
		return false, ErrNotInitialized
	}

	key, err := l.keys.ForEmail(
		ActionResendVerification,
		email,
	)
	if err != nil {
		return false, fmt.Errorf(
			"build resend-verification email rate-limit key: %w",
			err,
		)
	}

	result, err := l.limiter.Allow(
		ctx,
		key,
		requestID,
		l.policy.EmailLimit,
		l.policy.EmailWindow,
	)
	if err != nil {
		return false, fmt.Errorf(
			"check resend-verification email rate limit: %w",
			err,
		)
	}

	return result.Allowed, nil
}

var _ appresendverification.RateLimiter = (*ResendVerificationLimiter)(nil)
