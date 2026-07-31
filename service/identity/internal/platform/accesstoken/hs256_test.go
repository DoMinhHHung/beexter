package accesstoken

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	testSecret  = "0123456789abcdef0123456789abcdef"
	testSubject = identity.ID(
		"0198f124-659f-7cbd-a441-dc7eea175073",
	)
	testDeviceID = "0198f124-659f-7cbd-a441-dc7eea175074"
	testJTI      = "0198f124-659f-7cbd-a441-dc7eea175075"
)

var tokenTestNow = time.Date(
	2026,
	time.July,
	30,
	12,
	0,
	0,
	0,
	time.UTC,
)

func TestHS256IssueAndVerify(t *testing.T) {
	t.Parallel()

	service, err := New(testSecret)
	if err != nil {
		t.Fatalf("create token service: %v", err)
	}

	token, expiresAt, err := service.Issue(validClaims())
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	if !expiresAt.Equal(tokenTestNow.Add(time.Hour)) {
		t.Fatalf("unexpected expiration: %s", expiresAt)
	}

	claims, err := service.Verify(token, tokenTestNow)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}

	if claims.Subject != testSubject ||
		claims.DeviceID != testDeviceID ||
		claims.Role != identity.RoleClient ||
		!claims.EmailVerified ||
		claims.JTI != testJTI {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestHS256RejectsExpiredToken(t *testing.T) {
	t.Parallel()

	service, err := New(testSecret)
	if err != nil {
		t.Fatalf("create token service: %v", err)
	}

	token, _, err := service.Issue(validClaims())
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	_, err = service.Verify(token, tokenTestNow.Add(time.Hour))
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestHS256RejectsAlternateAlgorithm(t *testing.T) {
	t.Parallel()

	service, err := New(testSecret)
	if err != nil {
		t.Fatalf("create token service: %v", err)
	}

	token, _, err := service.Issue(validClaims())
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	parts := strings.Split(token, ".")
	parts[0] = base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"none","typ":"JWT"}`),
	)

	_, err = service.Verify(strings.Join(parts, "."), tokenTestNow)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestHS256RejectsTamperedPayload(t *testing.T) {
	t.Parallel()

	service, err := New(testSecret)
	if err != nil {
		t.Fatalf("create token service: %v", err)
	}

	token, _, err := service.Issue(validClaims())
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	parts := strings.Split(token, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString(
		[]byte(`{"sub":"tampered"}`),
	)

	_, err = service.Verify(strings.Join(parts, "."), tokenTestNow)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestHS256RejectsTokenWithoutDeviceID(t *testing.T) {
	t.Parallel()

	service, err := New(testSecret)
	if err != nil {
		t.Fatalf("create token service: %v", err)
	}

	headerSegment, err := encodeJSONSegment(tokenHeader{
		Algorithm: "HS256",
		Type:      "JWT",
	})
	if err != nil {
		t.Fatalf("encode header: %v", err)
	}

	legacyClaims := map[string]any{
		"sub":            testSubject.String(),
		"role":           string(identity.RoleClient),
		"email_verified": true,
		"iat":            tokenTestNow.Unix(),
		"exp":            tokenTestNow.Add(time.Hour).Unix(),
		"jti":            testJTI,
	}

	claimsJSON, err := json.Marshal(legacyClaims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	claimsSegment := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerSegment + "." + claimsSegment
	signature := base64.RawURLEncoding.EncodeToString(
		sign([]byte(testSecret), signingInput),
	)

	_, err = service.Verify(
		signingInput+"."+signature,
		tokenTestNow,
	)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func validClaims() appauth.AccessTokenClaims {
	return appauth.AccessTokenClaims{
		Subject:       testSubject,
		DeviceID:      testDeviceID,
		Role:          identity.RoleClient,
		EmailVerified: true,
		IssuedAt:      tokenTestNow,
		JTI:           testJTI,
	}
}
