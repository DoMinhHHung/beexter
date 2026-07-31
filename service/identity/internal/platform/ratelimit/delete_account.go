package ratelimit

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	appdeleteaccount "github.com/DoMinhHHung/beexster/service/identity/internal/application/deleteaccount"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

type DeleteAccountPolicy struct {
	IPLimit        int64
	IPWindow       time.Duration
	IdentityLimit  int64
	IdentityWindow time.Duration
}

type DeleteAccountLimiter struct {
	limiter *SlidingWindow
	keys    *KeyBuilder
	policy  DeleteAccountPolicy
}

func NewDeleteAccountLimiter(
	limiter *SlidingWindow,
	keys *KeyBuilder,
	policy DeleteAccountPolicy,
) (*DeleteAccountLimiter, error) {
	if limiter == nil || keys == nil {
		return nil, ErrNotInitialized
	}
	if policy.IPLimit <= 0 || policy.IdentityLimit <= 0 {
		return nil, ErrInvalidLimit
	}
	if policy.IPWindow <= 0 || policy.IdentityWindow <= 0 {
		return nil, ErrInvalidWindow
	}
	return &DeleteAccountLimiter{limiter: limiter, keys: keys, policy: policy}, nil
}

func (l *DeleteAccountLimiter) AllowDeleteAccountIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}
	key, err := l.keys.ForIP(ActionDeleteAccount, ipAddress)
	if err != nil {
		return false, fmt.Errorf("build delete-account IP key: %w", err)
	}
	result, err := l.limiter.Allow(
		ctx,
		key,
		requestID,
		l.policy.IPLimit,
		l.policy.IPWindow,
	)
	if err != nil {
		return false, fmt.Errorf("check delete-account IP limit: %w", err)
	}
	return result.Allowed, nil
}

func (l *DeleteAccountLimiter) AllowDeleteAccountIdentity(
	ctx context.Context,
	requestID string,
	identityID identity.ID,
) (bool, error) {
	if l == nil || l.limiter == nil || l.keys == nil {
		return false, ErrNotInitialized
	}
	key, err := l.keys.ForIdentity(ActionDeleteAccount, identityID)
	if err != nil {
		return false, fmt.Errorf("build delete-account identity key: %w", err)
	}
	result, err := l.limiter.Allow(
		ctx,
		key,
		requestID,
		l.policy.IdentityLimit,
		l.policy.IdentityWindow,
	)
	if err != nil {
		return false, fmt.Errorf("check delete-account identity limit: %w", err)
	}
	return result.Allowed, nil
}

var _ appdeleteaccount.RateLimiter = (*DeleteAccountLimiter)(nil)
