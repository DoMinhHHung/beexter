package resendverification

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestResendVerificationPersistsNormalizedLocale(t *testing.T) {
	t.Parallel()

	var persisted CreateParams
	useCase, err := New(
		&localeResendRepository{
			resend: func(params CreateParams) error {
				persisted = params
				return nil
			},
		},
		&localeResendUUIDGenerator{values: []string{
			"0198f124-659f-7cbd-a441-dc7eea175073",
			"0198f124-659f-7cbd-a441-dc7eea175074",
		}},
		localeResendRateLimiter{},
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
			Locale:    "vi-VN",
			IPAddress: netip.MustParseAddr("192.0.2.10"),
			RequestID: "request-1",
		},
	)
	if err != nil {
		t.Fatalf("execute resend verification: %v", err)
	}

	if persisted.Locale != "vi" {
		t.Fatalf("expected locale vi, got %q", persisted.Locale)
	}
}

type localeResendRepository struct {
	resend func(CreateParams) error
}

func (r *localeResendRepository) Resend(
	_ context.Context,
	params CreateParams,
) error {
	return r.resend(params)
}

type localeResendUUIDGenerator struct {
	values []string
	index  int
}

func (g *localeResendUUIDGenerator) GenerateString() (string, error) {
	if g.index >= len(g.values) {
		return "", errors.New("no UUID configured")
	}

	value := g.values[g.index]
	g.index++
	return value, nil
}

type localeResendRateLimiter struct{}

func (localeResendRateLimiter) AllowResendVerificationIP(
	context.Context,
	string,
	netip.Addr,
) (bool, error) {
	return true, nil
}

func (localeResendRateLimiter) AllowResendVerificationEmail(
	context.Context,
	string,
	string,
) (bool, error) {
	return true, nil
}
