package auth

import (
	"errors"
	"net/netip"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const RefreshTokenTTL = 7 * 24 * time.Hour

var (
	ErrRefreshTokenInvalid = errors.New("refresh token is invalid")
	ErrRefreshTokenExpired = errors.New("refresh token has expired")
	ErrRefreshTokenReuse   = errors.New("refresh token reuse was detected")
)

type AccessTokenClaims struct {
	Subject       identity.ID
	Role          identity.Role
	EmailVerified bool
	IssuedAt      time.Time
	JTI           string
}

type RefreshTokenClaims struct {
	UserID    identity.ID
	DeviceID  string
	TokenID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type Session struct {
	Token      string
	UserID     identity.ID
	DeviceID   string
	UserAgent  string
	IPAddress  netip.Addr
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
}

type Rotation struct {
	UserID             identity.ID
	DeviceID           string
	PresentedTokenID   string
	ReplacementTokenID string
	UserAgent          string
	IPAddress          netip.Addr
	ExpiresAt          time.Time
	LastUsedAt         time.Time
}
