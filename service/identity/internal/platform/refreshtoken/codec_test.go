package refreshtoken

import (
	"errors"
	"strings"
	"testing"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	testSecret   = "0123456789abcdef0123456789abcdef"
	testUserID   = identity.ID("0198f124-659f-7cbd-a441-dc7eea175071")
	testDeviceID = "0198f124-659f-7cbd-a441-dc7eea175072"
	testTokenID  = "0198f124-659f-7cbd-a441-dc7eea175073"
)

func TestCodecEncodeAndDecode(t *testing.T) {
	t.Parallel()

	codec, err := New(testSecret)
	if err != nil {
		t.Fatalf("create codec: %v", err)
	}

	token, err := codec.Encode(testUserID, testDeviceID, testTokenID)
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}

	claims, err := codec.Decode(token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}

	if claims.UserID != testUserID ||
		claims.DeviceID != testDeviceID ||
		claims.TokenID != testTokenID {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestCodecRejectsTampering(t *testing.T) {
	t.Parallel()

	codec, err := New(testSecret)
	if err != nil {
		t.Fatalf("create codec: %v", err)
	}

	token, err := codec.Encode(testUserID, testDeviceID, testTokenID)
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}

	parts := strings.Split(token, ".")
	parts[3] = "0198f124-659f-7cbd-a441-dc7eea175099"

	_, err = codec.Decode(strings.Join(parts, "."))
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestCodecRequiresDistinctStrongSecret(t *testing.T) {
	t.Parallel()

	_, err := New("short")
	if !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("expected ErrInvalidSecret, got %v", err)
	}
}
