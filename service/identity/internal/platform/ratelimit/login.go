package ratelimit

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	applogin "github.com/DoMinhHHung/beexster/service/identity/internal/application/login"
)

type LoginPolicy struct {
	IPLimit     int64
	IPWindow    time.Duration
	EmailLimit  int64
	EmailWindow time.Duration
}

type LoginLimiter struct {
	limiter *SlidingWindow
	keys    *KeyBuilder
	policy  LoginPolicy
}

func NewLoginLimiter(
	limiter *SlidingWindow,
	keys *KeyBuilder,
	policy LoginPolicy,
) (*LoginLimiter, error) {
	if limiter == nil || keys == nil {
		return nil, ErrNotInitialized
	}

	if policy.IPLimit <= 0 || policy.EmailLimit <= 0 {
		return nil, ErrInvalidLimit
	}

	if policy.IPWindow <= 0 || policy.EmailWindow <= 0 {
		return nil, ErrInvalidWindow
	}

	return &LoginLimiter{
		limiter: limiter,
		keys:    keys,
		policy:  policy,
	}, nil
}

func (l *LoginLimiter) AllowLoginIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}

	key, err := l.keys.ForIP(ActionLogin, ipAddress)
	if err != nil {
		return false, fmt.Errorf(
			"build login IP rate-limit key: %w",
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
			"check login IP rate limit: %w",
			err,
		)
	}

	return result.Allowed, nil
}

func (l *LoginLimiter) AllowLoginEmail(
	ctx context.Context,
	requestID string,
	email string,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}

	key, err := l.keys.ForEmail(ActionLogin, email)
	if err != nil {
		return false, fmt.Errorf(
			"build login email rate-limit key: %w",
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
			"check login email rate limit: %w",
			err,
		)
	}

	return result.Allowed, nil
}

var _ applogin.RateLimiter = (*LoginLimiter)(nil)
