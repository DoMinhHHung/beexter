package ratelimit

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	appreactivation "github.com/DoMinhHHung/beexster/service/identity/internal/application/requestreactivation"
)

type ReactivationPolicy struct {
	IPLimit     int64
	IPWindow    time.Duration
	EmailLimit  int64
	EmailWindow time.Duration
}

type ReactivationLimiter struct {
	limiter *SlidingWindow
	keys    *KeyBuilder
	policy  ReactivationPolicy
}

func NewReactivationLimiter(
	limiter *SlidingWindow,
	keys *KeyBuilder,
	policy ReactivationPolicy,
) (*ReactivationLimiter, error) {
	if limiter == nil || keys == nil {
		return nil, ErrNotInitialized
	}
	if policy.IPLimit <= 0 || policy.EmailLimit <= 0 {
		return nil, ErrInvalidLimit
	}
	if policy.IPWindow <= 0 || policy.EmailWindow <= 0 {
		return nil, ErrInvalidWindow
	}
	return &ReactivationLimiter{limiter: limiter, keys: keys, policy: policy}, nil
}

func (l *ReactivationLimiter) AllowReactivationIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}
	key, err := l.keys.ForIP(ActionReactivation, ipAddress)
	if err != nil {
		return false, fmt.Errorf("build reactivation IP key: %w", err)
	}
	result, err := l.limiter.Allow(
		ctx,
		key,
		requestID,
		l.policy.IPLimit,
		l.policy.IPWindow,
	)
	if err != nil {
		return false, fmt.Errorf("check reactivation IP limit: %w", err)
	}
	return result.Allowed, nil
}

func (l *ReactivationLimiter) AllowReactivationEmail(
	ctx context.Context,
	requestID string,
	email string,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}
	key, err := l.keys.ForEmail(ActionReactivation, email)
	if err != nil {
		return false, fmt.Errorf("build reactivation email key: %w", err)
	}
	result, err := l.limiter.Allow(
		ctx,
		key,
		requestID,
		l.policy.EmailLimit,
		l.policy.EmailWindow,
	)
	if err != nil {
		return false, fmt.Errorf("check reactivation email limit: %w", err)
	}
	return result.Allowed, nil
}

var _ appreactivation.RateLimiter = (*ReactivationLimiter)(nil)
