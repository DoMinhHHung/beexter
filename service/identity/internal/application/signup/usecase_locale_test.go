package signup

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func TestSignupPersistsNormalizedLocale(t *testing.T) {
	t.Parallel()

	var persisted CreateParams
	useCase, err := New(
		&localeSignupRepository{
			create: func(params CreateParams) error {
				persisted = params
				return nil
			},
		},
		localeSignupHasher{},
		localeSignupIdentityGenerator{},
		&localeSignupUUIDGenerator{values: []string{
			"0198f124-659f-7cbd-a441-dc7eea175074",
			"0198f124-659f-7cbd-a441-dc7eea175075",
		}},
		localeSignupRateLimiter{},
		func() time.Time {
			return time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
		},
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	_, err = useCase.Execute(
		context.Background(),
		Input{
			Email:     "user@example.com",
			Password:  "Secure1!",
			Locale:    "JA-jp",
			IPAddress: netip.MustParseAddr("192.0.2.10"),
			RequestID: "request-1",
		},
	)
	if err != nil {
		t.Fatalf("execute signup: %v", err)
	}

	if persisted.Locale != "ja" {
		t.Fatalf("expected locale ja, got %q", persisted.Locale)
	}
}

type localeSignupRepository struct {
	create func(CreateParams) error
}

func (r *localeSignupRepository) Create(
	_ context.Context,
	params CreateParams,
) error {
	return r.create(params)
}

type localeSignupHasher struct{}

func (localeSignupHasher) Hash(string) (string, error) {
	return "$argon2id$test", nil
}

type localeSignupIdentityGenerator struct{}

func (localeSignupIdentityGenerator) Generate() (identity.ID, error) {
	return identity.ID("0198f124-659f-7cbd-a441-dc7eea175073"), nil
}

type localeSignupUUIDGenerator struct {
	values []string
	index  int
}

func (g *localeSignupUUIDGenerator) GenerateString() (string, error) {
	if g.index >= len(g.values) {
		return "", errors.New("no UUID configured")
	}

	value := g.values[g.index]
	g.index++
	return value, nil
}

type localeSignupRateLimiter struct{}

func (localeSignupRateLimiter) AllowSignupIP(
	context.Context,
	string,
	netip.Addr,
) (bool, error) {
	return true, nil
}

func (localeSignupRateLimiter) AllowSignupEmail(
	context.Context,
	string,
	string,
) (bool, error) {
	return true, nil
}
