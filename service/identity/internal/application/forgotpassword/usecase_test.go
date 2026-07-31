package forgotpassword

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

const (
	testResetTokenID = "0198f124-659f-7cbd-a441-dc7eea175073"
	testOutboxID     = "0198f124-659f-7cbd-a441-dc7eea175074"
)

var forgotPasswordTestNow = time.Date(
	2026,
	time.July,
	30,
	14,
	45,
	0,
	0,
	time.FixedZone("ICT", 7*60*60),
)

func TestUseCaseCreatesPasswordResetRequest(t *testing.T) {
	t.Parallel()

	var (
		callOrder []string
		persisted CreateParams
	)

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			requestReset: func(
				_ context.Context,
				params CreateParams,
			) error {
				callOrder = append(callOrder, "repository")
				persisted = params
				return nil
			},
		},
		&fakeUUIDGenerator{
			values:    []string{testResetTokenID, testOutboxID},
			callOrder: &callOrder,
		},
		&fakeRateLimiter{
			allowIP: func(
				_ context.Context,
				requestID string,
				ipAddress netip.Addr,
			) (bool, error) {
				callOrder = append(callOrder, "ip_rate_limit")
				if requestID != "request-1" {
					t.Fatalf("unexpected request ID %q", requestID)
				}
				if ipAddress.String() != "192.0.2.10" {
					t.Fatalf("unexpected IP %s", ipAddress)
				}
				return true, nil
			},
			allowEmail: func(
				_ context.Context,
				requestID string,
				email string,
			) (bool, error) {
				callOrder = append(callOrder, "email_rate_limit")
				if requestID != "request-1" {
					t.Fatalf("unexpected request ID %q", requestID)
				}
				if email != "user@example.com" {
					t.Fatalf("unexpected email %q", email)
				}
				return true, nil
			},
		},
	)

	output, err := useCase.Execute(
		context.Background(),
		Input{
			Email:     " User@Example.COM ",
			Locale:    "ja-JP",
			IPAddress: netip.MustParseAddr("192.0.2.10"),
			RequestID: "request-1",
		},
	)
	if err != nil {
		t.Fatalf("execute forgot-password: %v", err)
	}

	if !output.Accepted {
		t.Fatal("expected accepted response")
	}

	expectedOrder := []string{
		"ip_rate_limit",
		"email_rate_limit",
		"uuid",
		"uuid",
		"repository",
	}
	if !reflect.DeepEqual(callOrder, expectedOrder) {
		t.Fatalf("expected call order %v, got %v", expectedOrder, callOrder)
	}

	if persisted.Email != "user@example.com" {
		t.Fatalf("unexpected email %q", persisted.Email)
	}
	if persisted.Locale != "ja" {
		t.Fatalf("expected locale ja, got %q", persisted.Locale)
	}
	if persisted.PasswordResetTokenID != testResetTokenID {
		t.Fatalf("unexpected token ID %q", persisted.PasswordResetTokenID)
	}
	if persisted.OutboxEventID != testOutboxID {
		t.Fatalf("unexpected outbox ID %q", persisted.OutboxEventID)
	}

	expectedCreatedAt := forgotPasswordTestNow.UTC()
	if !persisted.CreatedAt.Equal(expectedCreatedAt) {
		t.Fatalf("expected created_at %s, got %s", expectedCreatedAt, persisted.CreatedAt)
	}
	if !persisted.PasswordResetTokenExpiresAt.Equal(expectedCreatedAt.Add(time.Hour)) {
		t.Fatalf(
			"expected expiry %s, got %s",
			expectedCreatedAt.Add(time.Hour),
			persisted.PasswordResetTokenExpiresAt,
		)
	}
}

func TestUseCaseStopsWhenIPRateLimited(t *testing.T) {
	t.Parallel()

	emailLimiterCalled := false
	repositoryCalled := false

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			requestReset: func(context.Context, CreateParams) error {
				repositoryCalled = true
				return nil
			},
		},
		&fakeUUIDGenerator{values: []string{testResetTokenID, testOutboxID}},
		&fakeRateLimiter{
			allowIP: func(context.Context, string, netip.Addr) (bool, error) {
				return false, nil
			},
			allowEmail: func(context.Context, string, string) (bool, error) {
				emailLimiterCalled = true
				return true, nil
			},
		},
	)

	_, err := useCase.Execute(context.Background(), validInput())
	assertDomainCode(t, err, domain.ErrRateLimited)

	if emailLimiterCalled {
		t.Fatal("email limiter must not run after IP rejection")
	}
	if repositoryCalled {
		t.Fatal("repository must not run after rate-limit rejection")
	}
}

func TestUseCaseFailsClosedWhenRateLimiterFails(t *testing.T) {
	t.Parallel()

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			requestReset: func(context.Context, CreateParams) error {
				t.Fatal("repository must not be called")
				return nil
			},
		},
		&fakeUUIDGenerator{values: []string{testResetTokenID, testOutboxID}},
		&fakeRateLimiter{
			allowIP: func(context.Context, string, netip.Addr) (bool, error) {
				return false, errors.New("redis unavailable")
			},
			allowEmail: allowEmail,
		},
	)

	_, err := useCase.Execute(context.Background(), validInput())
	assertDomainCode(t, err, domain.ErrInternal)
}

func newTestUseCase(
	t *testing.T,
	repository Repository,
	ids UUIDGenerator,
	rateLimiter RateLimiter,
) *UseCase {
	t.Helper()

	useCase, err := New(
		repository,
		ids,
		rateLimiter,
		func() time.Time { return forgotPasswordTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	return useCase
}

func validInput() Input {
	return Input{
		Email:     "user@example.com",
		Locale:    "en",
		IPAddress: netip.MustParseAddr("192.0.2.10"),
		RequestID: "request-1",
	}
}

func allowEmail(context.Context, string, string) (bool, error) {
	return true, nil
}

func assertDomainCode(
	t *testing.T,
	err error,
	expectedCode domain.ErrorCode,
) {
	t.Helper()

	var domainError *domain.Error
	if !errors.As(err, &domainError) {
		t.Fatalf("expected domain error, got %v", err)
	}
	if domainError.Code != expectedCode {
		t.Fatalf("expected code %q, got %q", expectedCode, domainError.Code)
	}
}

type fakeRepository struct {
	requestReset func(context.Context, CreateParams) error
}

func (f *fakeRepository) RequestReset(
	ctx context.Context,
	params CreateParams,
) error {
	return f.requestReset(ctx, params)
}

type fakeUUIDGenerator struct {
	values    []string
	index     int
	callOrder *[]string
}

func (f *fakeUUIDGenerator) GenerateString() (string, error) {
	if f.callOrder != nil {
		*f.callOrder = append(*f.callOrder, "uuid")
	}
	if f.index >= len(f.values) {
		return "", errors.New("no UUID configured")
	}

	value := f.values[f.index]
	f.index++
	return value, nil
}

type fakeRateLimiter struct {
	allowIP    func(context.Context, string, netip.Addr) (bool, error)
	allowEmail func(context.Context, string, string) (bool, error)
}

func (f *fakeRateLimiter) AllowForgotPasswordIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	return f.allowIP(ctx, requestID, ipAddress)
}

func (f *fakeRateLimiter) AllowForgotPasswordEmail(
	ctx context.Context,
	requestID string,
	email string,
) (bool, error) {
	return f.allowEmail(ctx, requestID, email)
}
