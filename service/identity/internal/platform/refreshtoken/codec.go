package refreshtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	applogin "github.com/DoMinhHHung/beexter/service/identity/internal/application/login"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/google/uuid"
)

const (
	version             = "rt1"
	minimumSecretLength = 32
)

var (
	ErrNotInitialized = errors.New("refresh-token codec is not initialized")
	ErrInvalidSecret  = errors.New("refresh-token secret must contain at least 32 bytes")
	ErrTokenInvalid   = errors.New("refresh token is invalid")
)

type Claims struct {
	UserID   identity.ID
	DeviceID string
	TokenID  string
}

type Codec struct {
	secret []byte
}

func New(secret string) (*Codec, error) {
	if len(secret) < minimumSecretLength {
		return nil, ErrInvalidSecret
	}

	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)

	return &Codec{
		secret: secretCopy,
	}, nil
}

func (c *Codec) Encode(
	userID identity.ID,
	deviceID string,
	tokenID string,
) (string, error) {
	if c == nil || len(c.secret) < minimumSecretLength {
		return "", ErrNotInitialized
	}

	if userID.IsZero() {
		return "", ErrTokenInvalid
	}

	if err := validateCanonicalUUIDV7(deviceID); err != nil {
		return "", fmt.Errorf(
			"%w: validate device ID: %v",
			ErrTokenInvalid,
			err,
		)
	}

	if err := validateCanonicalUUIDV7(tokenID); err != nil {
		return "", fmt.Errorf(
			"%w: validate token ID: %v",
			ErrTokenInvalid,
			err,
		)
	}

	payload := strings.Join(
		[]string{
			version,
			userID.String(),
			deviceID,
			tokenID,
		},
		".",
	)

	signature := sign(c.secret, payload)

	return payload + "." +
		base64.RawURLEncoding.EncodeToString(signature), nil
}

func (c *Codec) Decode(rawToken string) (Claims, error) {
	if c == nil || len(c.secret) < minimumSecretLength {
		return Claims{}, ErrNotInitialized
	}

	parts := strings.Split(rawToken, ".")
	if len(parts) != 5 || parts[0] != version {
		return Claims{}, ErrTokenInvalid
	}

	for _, part := range parts {
		if part == "" {
			return Claims{}, ErrTokenInvalid
		}
	}

	payload := strings.Join(parts[:4], ".")
	receivedSignature, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil || len(receivedSignature) != sha256.Size {
		return Claims{}, ErrTokenInvalid
	}

	expectedSignature := sign(c.secret, payload)
	if !hmac.Equal(receivedSignature, expectedSignature) {
		return Claims{}, ErrTokenInvalid
	}

	userID, err := identity.ParseID(parts[1])
	if err != nil {
		return Claims{}, ErrTokenInvalid
	}

	if err := validateCanonicalUUIDV7(parts[2]); err != nil {
		return Claims{}, ErrTokenInvalid
	}

	if err := validateCanonicalUUIDV7(parts[3]); err != nil {
		return Claims{}, ErrTokenInvalid
	}

	return Claims{
		UserID:   userID,
		DeviceID: parts[2],
		TokenID:  parts[3],
	}, nil
}

func sign(secret []byte, payload string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
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

var _ applogin.RefreshTokenEncoder = (*Codec)(nil)
