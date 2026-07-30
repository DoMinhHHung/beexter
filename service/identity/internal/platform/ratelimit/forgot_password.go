package ratelimit

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	appforgotpassword "github.com/DoMinhHHung/beexter/service/identity/internal/application/forgotpassword"
)

type ForgotPasswordPolicy struct {
	IPLimit     int64
	IPWindow    time.Duration
	EmailLimit  int64
	EmailWindow time.Duration
}

type ForgotPasswordLimiter struct {
	limiter *SlidingWindow
	keys    *KeyBuilder
	policy  ForgotPasswordPolicy
}

func NewForgotPasswordLimiter(
	limiter *SlidingWindow,
	keys *KeyBuilder,
	policy ForgotPasswordPolicy,
) (*ForgotPasswordLimiter, error) {
	if limiter == nil || keys == nil {
		return nil, ErrNotInitialized
	}
	if policy.IPLimit <= 0 || policy.EmailLimit <= 0 {
		return nil, ErrInvalidLimit
	}
	if policy.IPWindow <= 0 || policy.EmailWindow <= 0 {
		return nil, ErrInvalidWindow
	}

	return &ForgotPasswordLimiter{
		limiter: limiter,
		keys:    keys,
		policy:  policy,
	}, nil
}

func (l *ForgotPasswordLimiter) AllowForgotPasswordIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}

	key, err := l.keys.ForIP(ActionForgotPassword, ipAddress)
	if err != nil {
		return false, fmt.Errorf("build forgot-password IP rate-limit key: %w", err)
	}

	result, err := l.limiter.Allow(
		ctx,
		key,
		requestID,
		l.policy.IPLimit,
		l.policy.IPWindow,
	)
	if err != nil {
		return false, fmt.Errorf("check forgot-password IP rate limit: %w", err)
	}

	return result.Allowed, nil
}

func (l *ForgotPasswordLimiter) AllowForgotPasswordEmail(
	ctx context.Context,
	requestID string,
	email string,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}

	key, err := l.keys.ForEmail(ActionForgotPassword, email)
	if err != nil {
		return false, fmt.Errorf("build forgot-password email rate-limit key: %w", err)
	}

	result, err := l.limiter.Allow(
		ctx,
		key,
		requestID,
		l.policy.EmailLimit,
		l.policy.EmailWindow,
	)
	if err != nil {
		return false, fmt.Errorf("check forgot-password email rate limit: %w", err)
	}

	return result.Allowed, nil
}

var _ appforgotpassword.RateLimiter = (*ForgotPasswordLimiter)(nil)
