package auth

import (
	"errors"
	"net/netip"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const RefreshTokenTTL = 7 * 24 * time.Hour

var (
	ErrAccessTokenInvalid  = errors.New("access token is invalid")
	ErrAccessTokenExpired  = errors.New("access token has expired")
	ErrRefreshTokenInvalid = errors.New("refresh token is invalid")
	ErrRefreshTokenExpired = errors.New("refresh token has expired")
	ErrRefreshTokenReuse   = errors.New("refresh token reuse was detected")
)

type AccessTokenClaims struct {
	Subject      identity.ID
	DeviceID     string
	PlatformRole identity.PlatformRole
	IssuedAt     time.Time
	JTI          string
}

type VerifiedAccessToken struct {
	Subject      identity.ID
	DeviceID     string
	PlatformRole identity.PlatformRole
	IssuedAt     time.Time
	ExpiresAt    time.Time
	JTI          string
}

type Principal struct {
	UserID         identity.ID
	DeviceID       string
	PlatformRole   identity.PlatformRole
	AccessTokenJTI string
	IssuedAt       time.Time
	ExpiresAt      time.Time
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
