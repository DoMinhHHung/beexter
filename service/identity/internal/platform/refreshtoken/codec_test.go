package refreshtoken

import (
	"errors"
	"strings"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

const testSecret = "0123456789abcdef0123456789abcdef"

var codecTestNow = time.Date(
	2026,
	time.July,
	30,
	12,
	0,
	0,
	0,
	time.UTC,
)

func TestCodecRoundTrip(t *testing.T) {
	t.Parallel()

	codec, err := New(testSecret)
	if err != nil {
		t.Fatalf("create codec: %v", err)
	}

	claims := validClaims()
	rawToken, err := codec.Encode(claims)
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}

	decoded, err := codec.Decode(rawToken, codecTestNow)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}

	if decoded != claims {
		t.Fatalf("expected claims %+v, got %+v", claims, decoded)
	}
}

func TestCodecRejectsTampering(t *testing.T) {
	t.Parallel()

	codec, err := New(testSecret)
	if err != nil {
		t.Fatalf("create codec: %v", err)
	}

	rawToken, err := codec.Encode(validClaims())
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}

	parts := strings.Split(rawToken, ".")
	parts[1] = parts[1] + "A"

	_, err = codec.Decode(strings.Join(parts, "."), codecTestNow)
	if !errors.Is(err, appauth.ErrRefreshTokenInvalid) {
		t.Fatalf("expected invalid-token error, got %v", err)
	}
}

func TestCodecRejectsExpiredToken(t *testing.T) {
	t.Parallel()

	codec, err := New(testSecret)
	if err != nil {
		t.Fatalf("create codec: %v", err)
	}

	rawToken, err := codec.Encode(validClaims())
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}

	_, err = codec.Decode(
		rawToken,
		codecTestNow.Add(appauth.RefreshTokenTTL),
	)
	if !errors.Is(err, appauth.ErrRefreshTokenExpired) {
		t.Fatalf("expected expired-token error, got %v", err)
	}
}

func TestCodecRequiresFixedTTL(t *testing.T) {
	t.Parallel()

	codec, err := New(testSecret)
	if err != nil {
		t.Fatalf("create codec: %v", err)
	}

	claims := validClaims()
	claims.ExpiresAt = claims.ExpiresAt.Add(time.Second)

	_, err = codec.Encode(claims)
	if !errors.Is(err, appauth.ErrRefreshTokenInvalid) {
		t.Fatalf("expected invalid-token error, got %v", err)
	}
}

func validClaims() appauth.RefreshTokenClaims {
	return appauth.RefreshTokenClaims{
		UserID: identity.ID(
			"0198f124-659f-7cbd-a441-dc7eea175073",
		),
		DeviceID: "0198f124-659f-7cbd-a441-dc7eea175074",
		TokenID:  "0198f124-659f-7cbd-a441-dc7eea175075",
		IssuedAt: codecTestNow,
		ExpiresAt: codecTestNow.Add(
			appauth.RefreshTokenTTL,
		),
	}
}
