package accesstoken

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	applogin "github.com/DoMinhHHung/beexter/service/identity/internal/application/login"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/google/uuid"
)

const (
	minimumSecretLength = 32
	accessTokenTTL      = time.Hour
	allowedClockSkew    = time.Minute
)

var (
	ErrNotInitialized = errors.New("access-token service is not initialized")
	ErrInvalidSecret  = errors.New("JWT HS256 secret must contain at least 32 bytes")
	ErrTokenInvalid   = errors.New("access token is invalid")
	ErrTokenExpired   = errors.New("access token has expired")
)

type HS256 struct {
	secret []byte
}

type VerifiedClaims struct {
	Subject       identity.ID
	Role          identity.Role
	EmailVerified bool
	IssuedAt      time.Time
	ExpiresAt     time.Time
	JTI           string
}

type tokenHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type issuedClaims struct {
	Subject       string `json:"sub"`
	Role          string `json:"role"`
	EmailVerified bool   `json:"email_verified"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
	JTI           string `json:"jti"`
}

type parsedClaims struct {
	Subject       string `json:"sub"`
	Role          string `json:"role"`
	EmailVerified *bool  `json:"email_verified"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
	JTI           string `json:"jti"`
}

func New(secret string) (*HS256, error) {
	if len(secret) < minimumSecretLength {
		return nil, ErrInvalidSecret
	}

	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)

	return &HS256{
		secret: secretCopy,
	}, nil
}

func (s *HS256) Issue(
	claims applogin.AccessTokenClaims,
) (string, time.Time, error) {
	if s == nil || len(s.secret) < minimumSecretLength {
		return "", time.Time{}, ErrNotInitialized
	}

	if claims.Subject.IsZero() ||
		!claims.Role.IsValid() ||
		claims.IssuedAt.IsZero() {
		return "", time.Time{}, ErrTokenInvalid
	}

	if err := validateCanonicalUUIDV7(claims.JTI); err != nil {
		return "", time.Time{}, fmt.Errorf(
			"%w: validate JTI: %v",
			ErrTokenInvalid,
			err,
		)
	}

	issuedAt := claims.IssuedAt.UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(accessTokenTTL)

	headerSegment, err := encodeJSONSegment(tokenHeader{
		Algorithm: "HS256",
		Type:      "JWT",
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf(
			"encode JWT header: %w",
			err,
		)
	}

	claimsSegment, err := encodeJSONSegment(issuedClaims{
		Subject:       claims.Subject.String(),
		Role:          string(claims.Role),
		EmailVerified: claims.EmailVerified,
		IssuedAt:      issuedAt.Unix(),
		ExpiresAt:     expiresAt.Unix(),
		JTI:           claims.JTI,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf(
			"encode JWT claims: %w",
			err,
		)
	}

	signingInput := headerSegment + "." + claimsSegment
	signature := sign(s.secret, signingInput)

	return signingInput + "." +
			base64.RawURLEncoding.EncodeToString(signature),
		expiresAt,
		nil
}

func (s *HS256) Verify(
	rawToken string,
	now time.Time,
) (VerifiedClaims, error) {
	if s == nil || len(s.secret) < minimumSecretLength {
		return VerifiedClaims{}, ErrNotInitialized
	}

	if now.IsZero() {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 ||
		parts[0] == "" ||
		parts[1] == "" ||
		parts[2] == "" {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	var header tokenHeader
	if err := decodeJSONSegment(parts[0], &header); err != nil {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	if header.Algorithm != "HS256" || header.Type != "JWT" {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	receivedSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(receivedSignature) != sha256.Size {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	expectedSignature := sign(
		s.secret,
		parts[0]+"."+parts[1],
	)

	if !hmac.Equal(receivedSignature, expectedSignature) {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	var claims parsedClaims
	if err := decodeJSONSegment(parts[1], &claims); err != nil {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	if claims.Subject == "" ||
		claims.Role == "" ||
		claims.EmailVerified == nil ||
		claims.IssuedAt <= 0 ||
		claims.ExpiresAt <= 0 ||
		claims.JTI == "" {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	subject, err := identity.ParseID(claims.Subject)
	if err != nil {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	role := identity.Role(claims.Role)
	if !role.IsValid() {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	if err := validateCanonicalUUIDV7(claims.JTI); err != nil {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	if claims.ExpiresAt-claims.IssuedAt != int64(accessTokenTTL/time.Second) {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	nowUnix := now.UTC().Unix()
	if claims.IssuedAt > nowUnix+int64(allowedClockSkew/time.Second) {
		return VerifiedClaims{}, ErrTokenInvalid
	}

	if claims.ExpiresAt <= nowUnix {
		return VerifiedClaims{}, ErrTokenExpired
	}

	return VerifiedClaims{
		Subject:       subject,
		Role:          role,
		EmailVerified: *claims.EmailVerified,
		IssuedAt:      time.Unix(claims.IssuedAt, 0).UTC(),
		ExpiresAt:     time.Unix(claims.ExpiresAt, 0).UTC(),
		JTI:           claims.JTI,
	}, nil
}

func encodeJSONSegment(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeJSONSegment(
	segment string,
	destination any,
) error {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return err
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}

		return err
	}

	return nil
}

func sign(secret []byte, signingInput string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

func validateCanonicalUUIDV7(rawID string) error {
	parsedID, err := uuid.Parse(rawID)
	if err != nil {
		return err
	}

	if parsedID.Version() != 7 ||
		parsedID.Variant() != uuid.RFC4122 ||
		parsedID.String() != rawID {
		return errors.New("ID must be a canonical UUID v7")
	}

	return nil
}

var _ applogin.AccessTokenIssuer = (*HS256)(nil)
