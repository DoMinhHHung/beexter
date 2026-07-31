package signup

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	testIdentityID = identity.ID(
		"0198f124-659f-7cbd-a441-dc7eea175073",
	)
	testTokenID  = "0198f124-659f-7cbd-a441-dc7eea175074"
	testOutboxID = "0198f124-659f-7cbd-a441-dc7eea175075"
)

var testNow = time.Date(
	2026,
	time.July,
	30,
	2,
	30,
	0,
	0,
	time.UTC,
)

func TestUseCaseExecuteCreatesSignupAtomically(t *testing.T) {
	t.Parallel()

	var callOrder []string
	var persisted CreateParams

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			create: func(
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
		&fakeHasher{
			hash: func(password string) (string, error) {
				callOrder = append(callOrder, "hash")

				if password != "Secure1!" {
					t.Fatalf(
						"unexpected password: %q",
						password,
					)
				}

				return "$argon2id$test", nil
			},
		},
		&fakeIdentityIDGenerator{
			generate: func() (identity.ID, error) {
				callOrder = append(
					callOrder,
					"identity_id",
				)
				return testIdentityID, nil
			},
		},
		&fakeUUIDGenerator{
			values:    []string{testTokenID, testOutboxID},
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
						"unexpected request ID: %q",
						requestID,
					)
				}

				if ipAddress.String() != "192.0.2.10" {
					t.Fatalf(
						"unexpected IP: %s",
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
						"unexpected request ID: %q",
						requestID,
					)
				}

				if email != "user@example.com" {
					t.Fatalf(
						"expected normalized email, got %q",
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
			Email:     " User@Example.COM ",
			Password:  "Secure1!",
			IPAddress: netip.MustParseAddr("192.0.2.10"),
			RequestID: "request-1",
		},
	)
	if err != nil {
		t.Fatalf("execute signup: %v", err)
	}

	expectedOrder := []string{
		"ip_rate_limit",
		"email_rate_limit",
		"hash",
		"identity_id",
		"uuid",
		"uuid",
		"repository",
	}

	if !reflect.DeepEqual(callOrder, expectedOrder) {
		t.Fatalf(
			"expected call order %v, got %v",
			expectedOrder,
			callOrder,
		)
	}

	if output.ID != testIdentityID ||
		output.Email != "user@example.com" {
		t.Fatalf("unexpected output: %+v", output)
	}

	if persisted.PasswordHash != "$argon2id$test" {
		t.Fatalf(
			"unexpected password hash: %q",
			persisted.PasswordHash,
		)
	}

	if persisted.Status != identity.StatusActive {
		t.Fatalf(
			"unexpected status: %q",
			persisted.Status,
		)
	}

	if !persisted.CreatedAt.Equal(testNow) {
		t.Fatalf(
			"unexpected created time: %s",
			persisted.CreatedAt,
		)
	}

	expectedExpiry := testNow.Add(time.Hour)

	if !persisted.VerificationTokenExpiresAt.Equal(
		expectedExpiry,
	) {
		t.Fatalf(
			"expected expiry %s, got %s",
			expectedExpiry,
			persisted.VerificationTokenExpiresAt,
		)
	}
}

func TestUseCaseStopsBeforeHashWhenIPRateLimited(
	t *testing.T,
) {
	t.Parallel()

	emailLimiterCalled := false
	hasherCalled := false
	repositoryCalled := false

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			create: func(
				context.Context,
				CreateParams,
			) error {
				repositoryCalled = true
				return nil
			},
		},
		&fakeHasher{
			hash: func(string) (string, error) {
				hasherCalled = true
				return "$argon2id$test", nil
			},
		},
		&fakeIdentityIDGenerator{
			generate: validIdentityID,
		},
		&fakeUUIDGenerator{
			values: []string{testTokenID, testOutboxID},
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

	if hasherCalled {
		t.Fatal(
			"password hashing must not run after rate-limit rejection",
		)
	}

	if repositoryCalled {
		t.Fatal(
			"repository must not run after rate-limit rejection",
		)
	}
}

func TestUseCaseMapsDuplicateEmail(t *testing.T) {
	t.Parallel()

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			create: func(
				context.Context,
				CreateParams,
			) error {
				return ErrEmailAlreadyExists
			},
		},
		&fakeHasher{hash: validHash},
		&fakeIdentityIDGenerator{
			generate: validIdentityID,
		},
		&fakeUUIDGenerator{
			values: []string{testTokenID, testOutboxID},
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
		domain.ErrEmailAlreadyExists,
	)
}

func TestUseCaseFailsClosedOnRateLimiterError(
	t *testing.T,
) {
	t.Parallel()

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			create: func(
				context.Context,
				CreateParams,
			) error {
				return nil
			},
		},
		&fakeHasher{hash: validHash},
		&fakeIdentityIDGenerator{
			generate: validIdentityID,
		},
		&fakeUUIDGenerator{
			values: []string{testTokenID, testOutboxID},
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
}

func newTestUseCase(
	t *testing.T,
	repository Repository,
	hasher PasswordHasher,
	identityIDs IdentityIDGenerator,
	uuidIDs UUIDGenerator,
	rateLimiter RateLimiter,
) *UseCase {
	t.Helper()

	useCase, err := New(
		repository,
		hasher,
		identityIDs,
		uuidIDs,
		rateLimiter,
		func() time.Time {
			return testNow
		},
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	return useCase
}

func validInput() Input {
	return Input{
		Email:     "user@example.com",
		Password:  "Secure1!",
		IPAddress: netip.MustParseAddr("192.0.2.10"),
		RequestID: "request-1",
	}
}

func validHash(string) (string, error) {
	return "$argon2id$test", nil
}

func validIdentityID() (identity.ID, error) {
	return testIdentityID, nil
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
	expected domain.ErrorCode,
) {
	t.Helper()

	var domainError *domain.Error

	if !errors.As(err, &domainError) {
		t.Fatalf(
			"expected domain error, got %v",
			err,
		)
	}

	if domainError.Code != expected {
		t.Fatalf(
			"expected error code %q, got %q",
			expected,
			domainError.Code,
		)
	}
}

type fakeRepository struct {
	create func(context.Context, CreateParams) error
}

func (f *fakeRepository) Create(
	ctx context.Context,
	params CreateParams,
) error {
	return f.create(ctx, params)
}

type fakeHasher struct {
	hash func(string) (string, error)
}

func (f *fakeHasher) Hash(
	password string,
) (string, error) {
	return f.hash(password)
}

type fakeIdentityIDGenerator struct {
	generate func() (identity.ID, error)
}

func (f *fakeIdentityIDGenerator) Generate() (
	identity.ID,
	error,
) {
	return f.generate()
}

type fakeUUIDGenerator struct {
	values    []string
	index     int
	callOrder *[]string
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

func (f *fakeRateLimiter) AllowSignupIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	return f.allowIP(ctx, requestID, ipAddress)
}

func (f *fakeRateLimiter) AllowSignupEmail(
	ctx context.Context,
	requestID string,
	email string,
) (bool, error) {
	return f.allowEmail(ctx, requestID, email)
}
