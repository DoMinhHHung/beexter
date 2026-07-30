package resendverification

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
	testVerificationTokenID = "0198f124-659f-7cbd-a441-dc7eea175073"

	testOutboxEventID = "0198f124-659f-7cbd-a441-dc7eea175074"
)

var resendVerificationTestNow = time.Date(
	2026,
	time.July,
	30,
	11,
	0,
	0,
	0,
	time.UTC,
)

func TestUseCaseCreatesVerificationRequest(t *testing.T) {
	t.Parallel()

	var (
		callOrder []string
		persisted CreateParams
	)

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			resend: func(
				_ context.Context,
				params CreateParams,
			) error {
				callOrder = append(
					callOrder,
					"repository",
				)

				persisted = params

				return nil
			},
		},
		&fakeUUIDGenerator{
			values: []string{
				testVerificationTokenID,
				testOutboxEventID,
			},
			callOrder: &callOrder,
		},
		&fakeRateLimiter{
			allowIP: func(
				_ context.Context,
				requestID string,
				ipAddress netip.Addr,
			) (bool, error) {
				callOrder = append(
					callOrder,
					"ip_rate_limit",
				)

				if requestID != "request-1" {
					t.Fatalf(
						"unexpected request ID %q",
						requestID,
					)
				}

				if ipAddress.String() !=
					"192.0.2.10" {
					t.Fatalf(
						"unexpected IP address %s",
						ipAddress,
					)
				}

				return true, nil
			},
			allowEmail: func(
				_ context.Context,
				requestID string,
				email string,
			) (bool, error) {
				callOrder = append(
					callOrder,
					"email_rate_limit",
				)

				if requestID != "request-1" {
					t.Fatalf(
						"unexpected request ID %q",
						requestID,
					)
				}

				if email != "user@example.com" {
					t.Fatalf(
						"unexpected normalized email %q",
						email,
					)
				}

				return true, nil
			},
		},
	)

	output, err := useCase.Execute(
		context.Background(),
		Input{
			Email: " User@Example.COM ",
			IPAddress: netip.MustParseAddr(
				"192.0.2.10",
			),
			RequestID: "request-1",
		},
	)
	if err != nil {
		t.Fatalf(
			"execute resend verification: %v",
			err,
		)
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

	if !reflect.DeepEqual(
		callOrder,
		expectedOrder,
	) {
		t.Fatalf(
			"expected call order %v, got %v",
			expectedOrder,
			callOrder,
		)
	}

	if persisted.Email != "user@example.com" {
		t.Fatalf(
			"unexpected persisted email %q",
			persisted.Email,
		)
	}

	if persisted.VerificationTokenID !=
		testVerificationTokenID {
		t.Fatalf(
			"unexpected token ID %q",
			persisted.VerificationTokenID,
		)
	}

	if persisted.OutboxEventID !=
		testOutboxEventID {
		t.Fatalf(
			"unexpected outbox ID %q",
			persisted.OutboxEventID,
		)
	}

	if !persisted.CreatedAt.Equal(
		resendVerificationTestNow,
	) {
		t.Fatalf(
			"unexpected creation time %s",
			persisted.CreatedAt,
		)
	}

	expectedExpiry :=
		resendVerificationTestNow.Add(time.Hour)

	if !persisted.
		VerificationTokenExpiresAt.
		Equal(expectedExpiry) {
		t.Fatalf(
			"expected expiry %s, got %s",
			expectedExpiry,
			persisted.VerificationTokenExpiresAt,
		)
	}
}

func TestUseCaseStopsBeforeEmailProcessingWhenIPLimited(
	t *testing.T,
) {
	t.Parallel()

	var (
		emailLimiterCalled bool
		generatorCalled    bool
		repositoryCalled   bool
	)

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			resend: func(
				context.Context,
				CreateParams,
			) error {
				repositoryCalled = true
				return nil
			},
		},
		&fakeUUIDGenerator{
			generate: func() (string, error) {
				generatorCalled = true
				return testVerificationTokenID, nil
			},
		},
		&fakeRateLimiter{
			allowIP: func(
				context.Context,
				string,
				netip.Addr,
			) (bool, error) {
				return false, nil
			},
			allowEmail: func(
				context.Context,
				string,
				string,
			) (bool, error) {
				emailLimiterCalled = true
				return true, nil
			},
		},
	)

	_, err := useCase.Execute(
		context.Background(),
		validInput(),
	)

	assertDomainErrorCode(
		t,
		err,
		domain.ErrRateLimited,
	)

	if emailLimiterCalled {
		t.Fatal(
			"email limiter must not run after IP rejection",
		)
	}

	if generatorCalled {
		t.Fatal(
			"UUID generation must not run after rate-limit rejection",
		)
	}

	if repositoryCalled {
		t.Fatal(
			"repository must not run after rate-limit rejection",
		)
	}
}

func TestUseCaseFailsClosedWhenRedisFails(t *testing.T) {
	t.Parallel()

	repositoryCalled := false

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			resend: func(
				context.Context,
				CreateParams,
			) error {
				repositoryCalled = true
				return nil
			},
		},
		&fakeUUIDGenerator{
			values: []string{
				testVerificationTokenID,
				testOutboxEventID,
			},
		},
		&fakeRateLimiter{
			allowIP: func(
				context.Context,
				string,
				netip.Addr,
			) (bool, error) {
				return false, errors.New(
					"redis unavailable",
				)
			},
			allowEmail: allowEmail,
		},
	)

	_, err := useCase.Execute(
		context.Background(),
		validInput(),
	)

	assertDomainErrorCode(
		t,
		err,
		domain.ErrInternal,
	)

	if repositoryCalled {
		t.Fatal(
			"repository must not run when rate limiter fails",
		)
	}
}

func TestUseCaseMapsRepositoryFailureToInternal(
	t *testing.T,
) {
	t.Parallel()

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			resend: func(
				context.Context,
				CreateParams,
			) error {
				return errors.New(
					"database unavailable",
				)
			},
		},
		&fakeUUIDGenerator{
			values: []string{
				testVerificationTokenID,
				testOutboxEventID,
			},
		},
		&fakeRateLimiter{
			allowIP:    allowIP,
			allowEmail: allowEmail,
		},
	)

	_, err := useCase.Execute(
		context.Background(),
		validInput(),
	)

	assertDomainErrorCode(
		t,
		err,
		domain.ErrInternal,
	)
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
		func() time.Time {
			return resendVerificationTestNow
		},
	)
	if err != nil {
		t.Fatalf(
			"create resend-verification use case: %v",
			err,
		)
	}

	return useCase
}

func validInput() Input {
	return Input{
		Email: "user@example.com",
		IPAddress: netip.MustParseAddr(
			"192.0.2.10",
		),
		RequestID: "request-1",
	}
}

func allowIP(
	context.Context,
	string,
	netip.Addr,
) (bool, error) {
	return true, nil
}

func allowEmail(
	context.Context,
	string,
	string,
) (bool, error) {
	return true, nil
}

func assertDomainErrorCode(
	t *testing.T,
	err error,
	expectedCode domain.ErrorCode,
) {
	t.Helper()

	var domainError *domain.Error

	if !errors.As(err, &domainError) {
		t.Fatalf(
			"expected domain error, got %v",
			err,
		)
	}

	if domainError.Code != expectedCode {
		t.Fatalf(
			"expected code %q, got %q",
			expectedCode,
			domainError.Code,
		)
	}
}

type fakeRepository struct {
	resend func(
		context.Context,
		CreateParams,
	) error
}

func (f *fakeRepository) Resend(
	ctx context.Context,
	params CreateParams,
) error {
	return f.resend(ctx, params)
}

type fakeUUIDGenerator struct {
	values    []string
	index     int
	callOrder *[]string
	generate  func() (string, error)
}

func (f *fakeUUIDGenerator) GenerateString() (
	string,
	error,
) {
	if f.callOrder != nil {
		*f.callOrder = append(
			*f.callOrder,
			"uuid",
		)
	}

	if f.generate != nil {
		return f.generate()
	}

	if f.index >= len(f.values) {
		return "", errors.New(
			"no UUID value configured",
		)
	}

	value := f.values[f.index]
	f.index++

	return value, nil
}

type fakeRateLimiter struct {
	allowIP func(
		context.Context,
		string,
		netip.Addr,
	) (bool, error)

	allowEmail func(
		context.Context,
		string,
		string,
	) (bool, error)
}

func (f *fakeRateLimiter) AllowResendVerificationIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	return f.allowIP(
		ctx,
		requestID,
		ipAddress,
	)
}

func (f *fakeRateLimiter) AllowResendVerificationEmail(
	ctx context.Context,
	requestID string,
	email string,
) (bool, error) {
	return f.allowEmail(
		ctx,
		requestID,
		email,
	)
}
