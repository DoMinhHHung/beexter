package refreshtoken

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

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/google/uuid"
)

const (
	version             = "rt2"
	minimumSecretLength = 32
	allowedClockSkew    = time.Minute
)

var (
	ErrNotInitialized = errors.New("refresh-token codec is not initialized")
	ErrInvalidSecret  = errors.New("refresh-token secret must contain at least 32 bytes")
)

type Codec struct {
	secret []byte
}

type payload struct {
	Subject   string `json:"sub"`
	DeviceID  string `json:"device_id"`
	TokenID   string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func New(secret string) (*Codec, error) {
	if len(secret) < minimumSecretLength {
		return nil, ErrInvalidSecret
	}

	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)

	return &Codec{secret: secretCopy}, nil
}

func (c *Codec) Encode(
	claims appauth.RefreshTokenClaims,
) (string, error) {
	if c == nil || len(c.secret) < minimumSecretLength {
		return "", ErrNotInitialized
	}

	issuedAt := claims.IssuedAt.UTC().Truncate(time.Second)
	expiresAt := claims.ExpiresAt.UTC().Truncate(time.Second)

	if claims.UserID.IsZero() ||
		issuedAt.IsZero() ||
		expiresAt.IsZero() ||
		!expiresAt.Equal(issuedAt.Add(appauth.RefreshTokenTTL)) {
		return "", appauth.ErrRefreshTokenInvalid
	}

	if err := validateCanonicalUUIDV7(claims.DeviceID); err != nil {
		return "", fmt.Errorf(
			"%w: validate device ID: %v",
			appauth.ErrRefreshTokenInvalid,
			err,
		)
	}

	if err := validateCanonicalUUIDV7(claims.TokenID); err != nil {
		return "", fmt.Errorf(
			"%w: validate token ID: %v",
			appauth.ErrRefreshTokenInvalid,
			err,
		)
	}

	encodedPayload, err := json.Marshal(payload{
		Subject:   claims.UserID.String(),
		DeviceID:  claims.DeviceID,
		TokenID:   claims.TokenID,
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: expiresAt.Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("marshal refresh-token payload: %w", err)
	}

	payloadSegment := base64.RawURLEncoding.EncodeToString(encodedPayload)
	signingInput := version + "." + payloadSegment
	signature := sign(c.secret, signingInput)

	return signingInput + "." +
		base64.RawURLEncoding.EncodeToString(signature), nil
}

func (c *Codec) Decode(
	rawToken string,
	now time.Time,
) (appauth.RefreshTokenClaims, error) {
	if c == nil || len(c.secret) < minimumSecretLength {
		return appauth.RefreshTokenClaims{}, ErrNotInitialized
	}

	if now.IsZero() {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 ||
		parts[0] != version ||
		parts[1] == "" ||
		parts[2] == "" {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	receivedSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(receivedSignature) != sha256.Size {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	signingInput := parts[0] + "." + parts[1]
	expectedSignature := sign(c.secret, signingInput)
	if !hmac.Equal(receivedSignature, expectedSignature) {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	var tokenPayload payload
	decoder := json.NewDecoder(bytes.NewReader(decodedPayload))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&tokenPayload); err != nil {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	var trailingValue any
	if err := decoder.Decode(&trailingValue); !errors.Is(err, io.EOF) {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	if tokenPayload.Subject == "" ||
		tokenPayload.DeviceID == "" ||
		tokenPayload.TokenID == "" ||
		tokenPayload.IssuedAt <= 0 ||
		tokenPayload.ExpiresAt <= 0 ||
		tokenPayload.ExpiresAt-tokenPayload.IssuedAt !=
			int64(appauth.RefreshTokenTTL/time.Second) {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	userID, err := identity.ParseID(tokenPayload.Subject)
	if err != nil {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	if err := validateCanonicalUUIDV7(tokenPayload.DeviceID); err != nil {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	if err := validateCanonicalUUIDV7(tokenPayload.TokenID); err != nil {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	nowUnix := now.UTC().Unix()
	if tokenPayload.IssuedAt >
		nowUnix+int64(allowedClockSkew/time.Second) {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenInvalid
	}

	if tokenPayload.ExpiresAt <= nowUnix {
		return appauth.RefreshTokenClaims{}, appauth.ErrRefreshTokenExpired
	}

	return appauth.RefreshTokenClaims{
		UserID:    userID,
		DeviceID:  tokenPayload.DeviceID,
		TokenID:   tokenPayload.TokenID,
		IssuedAt:  time.Unix(tokenPayload.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(tokenPayload.ExpiresAt, 0).UTC(),
	}, nil
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
