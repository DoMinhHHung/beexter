package ratelimit

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	appsignup "github.com/DoMinhHHung/beexster/service/identity/internal/application/signup"
)

type SignupPolicy struct {
	IPLimit     int64
	IPWindow    time.Duration
	EmailLimit  int64
	EmailWindow time.Duration
}

type SignupLimiter struct {
	limiter *SlidingWindow
	keys    *KeyBuilder
	policy  SignupPolicy
}

func NewSignupLimiter(
	limiter *SlidingWindow,
	keys *KeyBuilder,
	policy SignupPolicy,
) (*SignupLimiter, error) {
	if limiter == nil || keys == nil {
		return nil, ErrNotInitialized
	}

	if policy.IPLimit <= 0 || policy.EmailLimit <= 0 {
		return nil, ErrInvalidLimit
	}

	if policy.IPWindow <= 0 || policy.EmailWindow <= 0 {
		return nil, ErrInvalidWindow
	}

	return &SignupLimiter{
		limiter: limiter,
		keys:    keys,
		policy:  policy,
	}, nil
}

func (l *SignupLimiter) AllowSignupIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}

	key, err := l.keys.ForIP(ActionSignup, ipAddress)
	if err != nil {
		return false, fmt.Errorf(
			"build signup IP rate-limit key: %w",
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
			"check signup IP rate limit: %w",
			err,
		)
	}

	return result.Allowed, nil
}

func (l *SignupLimiter) AllowSignupEmail(
	ctx context.Context,
	requestID string,
	email string,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}

	key, err := l.keys.ForEmail(ActionSignup, email)
	if err != nil {
		return false, fmt.Errorf(
			"build signup email rate-limit key: %w",
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
			"check signup email rate limit: %w",
			err,
		)
	}

	return result.Allowed, nil
}

var _ appsignup.RateLimiter = (*SignupLimiter)(nil)
