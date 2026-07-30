package accesstoken

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	applogin "github.com/DoMinhHHung/beexter/service/identity/internal/application/login"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	testSecret  = "0123456789abcdef0123456789abcdef"
	testSubject = identity.ID(
		"0198f124-659f-7cbd-a441-dc7eea175073",
	)
	testJTI = "0198f124-659f-7cbd-a441-dc7eea175074"
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

	token, expiresAt, err := service.Issue(
		applogin.AccessTokenClaims{
			Subject:       testSubject,
			Role:          identity.RoleClient,
			EmailVerified: true,
			IssuedAt:      tokenTestNow,
			JTI:           testJTI,
		},
	)
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

	token, _, err := service.Issue(
		applogin.AccessTokenClaims{
			Subject:       testSubject,
			Role:          identity.RoleClient,
			EmailVerified: true,
			IssuedAt:      tokenTestNow,
			JTI:           testJTI,
		},
	)
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

	token, _, err := service.Issue(
		applogin.AccessTokenClaims{
			Subject:       testSubject,
			Role:          identity.RoleClient,
			EmailVerified: true,
			IssuedAt:      tokenTestNow,
			JTI:           testJTI,
		},
	)
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

	token, _, err := service.Issue(
		applogin.AccessTokenClaims{
			Subject:       testSubject,
			Role:          identity.RoleClient,
			EmailVerified: true,
			IssuedAt:      tokenTestNow,
			JTI:           testJTI,
		},
	)
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
