package resetpassword

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

const (
	testTokenID = "0198f124-659f-7cbd-a441-dc7eea175073"
	testUserID  = identity.ID("0198f124-659f-7cbd-a441-dc7eea175074")
)

var resetPasswordTestNow = time.Date(
	2026,
	time.July,
	30,
	9,
	30,
	0,
	0,
	time.UTC,
)

func TestUseCaseResetsPasswordAndSchedulesSessionRevocation(
	t *testing.T,
) {
	t.Parallel()

	var (
		callOrder []string
		persisted ResetParams
	)

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			resolveTarget: func(
				_ context.Context,
				tokenID string,
				checkedAt time.Time,
			) (identity.ID, error) {
				callOrder = append(callOrder, "resolve")
				if tokenID != testTokenID {
					t.Fatalf("unexpected token ID %q", tokenID)
				}
				if !checkedAt.Equal(resetPasswordTestNow) {
					t.Fatalf("unexpected checked time %s", checkedAt)
				}
				return testUserID, nil
			},
			reset: func(
				_ context.Context,
				params ResetParams,
			) error {
				callOrder = append(callOrder, "reset")
				persisted = params
				return nil
			},
		},
		&fakeHasher{
			hash: func(password string) (string, error) {
				callOrder = append(callOrder, "hash")
				if password != "Secure2!" {
					t.Fatalf("unexpected password %q", password)
				}
				return "$argon2id$test", nil
			},
		},
		&fakeRateLimiter{
			allow: func(
				_ context.Context,
				requestID string,
				ipAddress netip.Addr,
			) (bool, error) {
				callOrder = append(callOrder, "rate_limit")
				if requestID != "request-1" {
					t.Fatalf("unexpected request ID %q", requestID)
				}
				if ipAddress.String() != "192.0.2.10" {
					t.Fatalf("unexpected IP address %s", ipAddress)
				}
				return true, nil
			},
		},
		&fakeSessionRevoker{
			revokeAll: func(
				_ context.Context,
				userID identity.ID,
			) error {
				callOrder = append(callOrder, "revoke_all")
				if userID != testUserID {
					t.Fatalf("unexpected user ID %q", userID)
				}
				return nil
			},
		},
	)

	output, err := useCase.Execute(
		context.Background(),
		validInput(),
	)
	if err != nil {
		t.Fatalf("execute reset-password: %v", err)
	}

	if !output.PasswordReset {
		t.Fatal("expected password_reset=true")
	}

	expectedOrder := []string{
		"rate_limit",
		"resolve",
		"hash",
		"revoke_all",
		"reset",
	}
	if !reflect.DeepEqual(callOrder, expectedOrder) {
		t.Fatalf(
			"expected call order %v, got %v",
			expectedOrder,
			callOrder,
		)
	}

	if persisted.IdentityID != testUserID ||
		persisted.PasswordResetTokenID != testTokenID ||
		persisted.PasswordHash != "$argon2id$test" {
		t.Fatalf("unexpected reset params: %+v", persisted)
	}

	if !persisted.ResetAt.Equal(resetPasswordTestNow) {
		t.Fatalf("unexpected reset time %s", persisted.ResetAt)
	}

	expectedAvailableAt := resetPasswordTestNow.Add(
		sessionRevocationGuardDelay,
	)
	if !persisted.SessionRevocationAvailableAt.Equal(
		expectedAvailableAt,
	) {
		t.Fatalf(
			"expected session revocation at %s, got %s",
			expectedAvailableAt,
			persisted.SessionRevocationAvailableAt,
		)
	}
}

func TestUseCaseFailsClosedWhenRateLimiterFails(t *testing.T) {
	t.Parallel()

	hasherCalled := false
	repositoryCalled := false

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			resolveTarget: func(
				context.Context,
				string,
				time.Time,
			) (identity.ID, error) {
				repositoryCalled = true
				return testUserID, nil
			},
			reset: func(context.Context, ResetParams) error {
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
		&fakeRateLimiter{
			allow: func(
				context.Context,
				string,
				netip.Addr,
			) (bool, error) {
				return false, errors.New("redis unavailable")
			},
		},
		&fakeSessionRevoker{revokeAll: allowRevocation},
	)

	_, err := useCase.Execute(context.Background(), validInput())
	assertDomainErrorCode(t, err, domain.ErrInternal)

	if hasherCalled {
		t.Fatal("hasher must not run when rate limiter fails")
	}
	if repositoryCalled {
		t.Fatal("repository must not run when rate limiter fails")
	}
}

func TestUseCaseDoesNotMutatePasswordWhenSessionRevocationFails(
	t *testing.T,
) {
	t.Parallel()

	resetCalled := false

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			resolveTarget: func(
				context.Context,
				string,
				time.Time,
			) (identity.ID, error) {
				return testUserID, nil
			},
			reset: func(context.Context, ResetParams) error {
				resetCalled = true
				return nil
			},
		},
		&fakeHasher{hash: validHash},
		&fakeRateLimiter{allow: allowRequest},
		&fakeSessionRevoker{
			revokeAll: func(
				context.Context,
				identity.ID,
			) error {
				return errors.New("redis unavailable")
			},
		},
	)

	_, err := useCase.Execute(context.Background(), validInput())
	assertDomainErrorCode(t, err, domain.ErrInternal)

	if resetCalled {
		t.Fatal(
			"password transaction must not run when session revocation fails",
		)
	}
}

func TestUseCaseMapsTokenErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		repositoryError error
		expectedCode    domain.ErrorCode
	}{
		{
			name:            "not found",
			repositoryError: ErrTokenNotFound,
			expectedCode:    domain.ErrTokenInvalid,
		},
		{
			name:            "already used",
			repositoryError: ErrTokenAlreadyUsed,
			expectedCode:    domain.ErrTokenInvalid,
		},
		{
			name:            "revoked",
			repositoryError: ErrTokenRevoked,
			expectedCode:    domain.ErrTokenInvalid,
		},
		{
			name:            "inactive account",
			repositoryError: ErrAccountInactive,
			expectedCode:    domain.ErrTokenInvalid,
		},
		{
			name:            "expired",
			repositoryError: ErrTokenExpired,
			expectedCode:    domain.ErrTokenExpired,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			useCase := newTestUseCase(
				t,
				&fakeRepository{
					resolveTarget: func(
						context.Context,
						string,
						time.Time,
					) (identity.ID, error) {
						return "", test.repositoryError
					},
					reset: func(context.Context, ResetParams) error {
						t.Fatal("reset must not run")
						return nil
					},
				},
				&fakeHasher{hash: validHash},
				&fakeRateLimiter{allow: allowRequest},
				&fakeSessionRevoker{revokeAll: allowRevocation},
			)

			_, err := useCase.Execute(
				context.Background(),
				validInput(),
			)
			assertDomainErrorCode(t, err, test.expectedCode)
		})
	}
}

func TestUseCaseRejectsInvalidPasswordBeforeHashing(t *testing.T) {
	t.Parallel()

	hasherCalled := false

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			resolveTarget: func(
				context.Context,
				string,
				time.Time,
			) (identity.ID, error) {
				t.Fatal("repository must not run")
				return "", nil
			},
			reset: func(context.Context, ResetParams) error {
				t.Fatal("repository must not run")
				return nil
			},
		},
		&fakeHasher{
			hash: func(string) (string, error) {
				hasherCalled = true
				return "", nil
			},
		},
		&fakeRateLimiter{allow: allowRequest},
		&fakeSessionRevoker{revokeAll: allowRevocation},
	)

	input := validInput()
	input.NewPassword = "weak"

	_, err := useCase.Execute(context.Background(), input)
	assertDomainErrorCode(t, err, domain.ErrInvalidInput)

	if hasherCalled {
		t.Fatal("hasher must not run for invalid password")
	}
}

func newTestUseCase(
	t *testing.T,
	repository Repository,
	hasher PasswordHasher,
	rateLimiter RateLimiter,
	sessionRevoker SessionRevoker,
) *UseCase {
	t.Helper()

	useCase, err := New(
		repository,
		hasher,
		rateLimiter,
		sessionRevoker,
		func() time.Time { return resetPasswordTestNow },
	)
	if err != nil {
		t.Fatalf("create reset-password use case: %v", err)
	}
	return useCase
}

func validInput() Input {
	return Input{
		Token:       testTokenID,
		NewPassword: "Secure2!",
		IPAddress:   netip.MustParseAddr("192.0.2.10"),
		RequestID:   "request-1",
	}
}

func validHash(string) (string, error) {
	return "$argon2id$test", nil
}

func allowRequest(
	context.Context,
	string,
	netip.Addr,
) (bool, error) {
	return true, nil
}

func allowRevocation(context.Context, identity.ID) error {
	return nil
}

func assertDomainErrorCode(
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
		t.Fatalf(
			"expected error code %q, got %q",
			expectedCode,
			domainError.Code,
		)
	}
}

type fakeRepository struct {
	resolveTarget func(
		context.Context,
		string,
		time.Time,
	) (identity.ID, error)
	reset func(context.Context, ResetParams) error
}

func (f *fakeRepository) ResolveTarget(
	ctx context.Context,
	tokenID string,
	checkedAt time.Time,
) (identity.ID, error) {
	return f.resolveTarget(ctx, tokenID, checkedAt)
}

func (f *fakeRepository) Reset(
	ctx context.Context,
	params ResetParams,
) error {
	return f.reset(ctx, params)
}

type fakeHasher struct {
	hash func(string) (string, error)
}

func (f *fakeHasher) Hash(password string) (string, error) {
	return f.hash(password)
}

type fakeRateLimiter struct {
	allow func(
		context.Context,
		string,
		netip.Addr,
	) (bool, error)
}

func (f *fakeRateLimiter) AllowResetPasswordIP(
	ctx context.Context,
	requestID string,
	ipAddress netip.Addr,
) (bool, error) {
	return f.allow(ctx, requestID, ipAddress)
}

type fakeSessionRevoker struct {
	revokeAll func(context.Context, identity.ID) error
}

func (f *fakeSessionRevoker) RevokeAll(
	ctx context.Context,
	userID identity.ID,
) error {
	return f.revokeAll(ctx, userID)
}
