package login

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

const (
	testAttemptID = "0198f124-659f-7cbd-a441-dc7eea175071"
	testDeviceID  = "0198f124-659f-7cbd-a441-dc7eea175072"
	testRefreshID = "0198f124-659f-7cbd-a441-dc7eea175073"
	testAccessJTI = "0198f124-659f-7cbd-a441-dc7eea175074"
	testUserID    = identity.ID("0198f124-659f-7cbd-a441-dc7eea175075")
)

var testNow = time.Date(
	2026,
	time.July,
	30,
	12,
	0,
	0,
	0,
	time.UTC,
)

func TestUseCaseLogsInAndRecordsSuccess(t *testing.T) {
	t.Parallel()

	var (
		recordedAttempt Attempt
		savedSession    Session
	)

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			account: validAccount(),
			record: func(attempt Attempt) error {
				recordedAttempt = attempt
				return nil
			},
		},
		&fakePasswordVerifier{
			verify: func(password string, hash string) (bool, error) {
				if password != "Secure1!" || hash != "$argon2id$stored" {
					t.Fatalf("unexpected password verification input")
				}
				return true, nil
			},
		},
		&fakeSessionStore{
			save: func(session Session) error {
				savedSession = session
				return nil
			},
		},
	)

	output, err := useCase.Execute(context.Background(), validInput())
	if err != nil {
		t.Fatalf("execute login: %v", err)
	}

	if output.AccessToken != "access-token" ||
		output.RefreshToken != "refresh-token" ||
		output.DeviceID != testDeviceID ||
		output.User.ID != testUserID {
		t.Fatalf("unexpected output: %+v", output)
	}

	if savedSession.Token != testRefreshID ||
		savedSession.UserID != testUserID ||
		savedSession.DeviceID != testDeviceID ||
		!savedSession.ExpiresAt.Equal(testNow.Add(appauth.RefreshTokenTTL)) {
		t.Fatalf("unexpected saved session: %+v", savedSession)
	}

	if !recordedAttempt.Success ||
		recordedAttempt.FailureCode != "" ||
		recordedAttempt.IdentityID == nil ||
		*recordedAttempt.IdentityID != testUserID {
		t.Fatalf("unexpected login attempt: %+v", recordedAttempt)
	}
}

func TestUseCaseUsesDummyHashForUnknownEmail(t *testing.T) {
	t.Parallel()

	var (
		dummyVerified bool
		recorded      Attempt
	)

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			findErr: ErrIdentityNotFound,
			record: func(attempt Attempt) error {
				recorded = attempt
				return nil
			},
		},
		&fakePasswordVerifier{
			verify: func(_ string, hash string) (bool, error) {
				if hash != "$argon2id$dummy" {
					t.Fatalf("expected dummy hash, got %q", hash)
				}
				dummyVerified = true
				return false, nil
			},
		},
		&fakeSessionStore{},
	)

	_, err := useCase.Execute(context.Background(), validInput())
	assertDomainCode(t, err, domain.ErrInvalidCredentials)

	if !dummyVerified {
		t.Fatal("expected dummy password verification")
	}

	if recorded.Success ||
		recorded.FailureCode != string(domain.ErrInvalidCredentials) ||
		recorded.IdentityID != nil {
		t.Fatalf("unexpected failed attempt: %+v", recorded)
	}
}

func TestUseCaseRejectsUnverifiedAccountAfterPasswordCheck(t *testing.T) {
	t.Parallel()

	account := validAccount()
	account.EmailVerified = false

	var recorded Attempt

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			account: account,
			record: func(attempt Attempt) error {
				recorded = attempt
				return nil
			},
		},
		&fakePasswordVerifier{
			verify: func(string, string) (bool, error) {
				return true, nil
			},
		},
		&fakeSessionStore{},
	)

	_, err := useCase.Execute(context.Background(), validInput())
	assertDomainCode(t, err, domain.ErrEmailNotVerified)

	if recorded.FailureCode != string(domain.ErrEmailNotVerified) {
		t.Fatalf("unexpected failure code %q", recorded.FailureCode)
	}
}

func TestUseCaseFailsClosedWhenSessionSaveFails(t *testing.T) {
	t.Parallel()

	var recorded Attempt

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			account: validAccount(),
			record: func(attempt Attempt) error {
				recorded = attempt
				return nil
			},
		},
		&fakePasswordVerifier{
			verify: func(string, string) (bool, error) {
				return true, nil
			},
		},
		&fakeSessionStore{
			save: func(Session) error {
				return errors.New("redis unavailable")
			},
		},
	)

	_, err := useCase.Execute(context.Background(), validInput())
	assertDomainCode(t, err, domain.ErrInternal)

	if recorded.Success || recorded.FailureCode != string(domain.ErrInternal) {
		t.Fatalf("unexpected failed attempt: %+v", recorded)
	}
}

func TestUseCaseDeletesSessionWhenSuccessAuditFails(t *testing.T) {
	t.Parallel()

	deleted := false

	useCase := newTestUseCase(
		t,
		&fakeRepository{
			account: validAccount(),
			record: func(Attempt) error {
				return errors.New("audit database unavailable")
			},
		},
		&fakePasswordVerifier{
			verify: func(string, string) (bool, error) {
				return true, nil
			},
		},
		&fakeSessionStore{
			save: func(Session) error { return nil },
			delete: func(identity.ID, string) error {
				deleted = true
				return nil
			},
		},
	)

	_, err := useCase.Execute(context.Background(), validInput())
	assertDomainCode(t, err, domain.ErrInternal)

	if !deleted {
		t.Fatal("expected refresh session compensation")
	}
}

func newTestUseCase(
	t *testing.T,
	repository Repository,
	passwordVerifier PasswordVerifier,
	sessions SessionStore,
) *UseCase {
	t.Helper()

	useCase, err := New(
		repository,
		passwordVerifier,
		&fakeUUIDGenerator{
			values: []string{
				testAttemptID,
				testDeviceID,
				testRefreshID,
				testAccessJTI,
			},
		},
		&fakeRateLimiter{},
		&fakeAccessTokenIssuer{},
		&fakeRefreshTokenEncoder{},
		sessions,
		"$argon2id$dummy",
		func() time.Time { return testNow },
	)
	if err != nil {
		t.Fatalf("create login use case: %v", err)
	}

	return useCase
}

func validInput() Input {
	return Input{
		Email:     "User@Example.COM",
		Password:  "Secure1!",
		IPAddress: netip.MustParseAddr("192.0.2.10"),
		UserAgent: "test-agent",
		RequestID: "request-1",
	}
}

func validAccount() identity.Identity {
	return identity.Identity{
		ID:            testUserID,
		Email:         "user@example.com",
		PasswordHash:  "$argon2id$stored",
		PlatformRole:  identity.PlatformRoleNone,
		Status:        identity.StatusActive,
		EmailVerified: true,
	}
}

func assertDomainCode(
	t *testing.T,
	err error,
	expected domain.ErrorCode,
) {
	t.Helper()

	var domainError *domain.Error
	if !errors.As(err, &domainError) {
		t.Fatalf("expected domain error, got %v", err)
	}

	if domainError.Code != expected {
		t.Fatalf("expected code %q, got %q", expected, domainError.Code)
	}
}

type fakeRepository struct {
	account identity.Identity
	findErr error
	record  func(Attempt) error
}

func (f *fakeRepository) FindByEmail(
	context.Context,
	string,
) (identity.Identity, error) {
	return f.account, f.findErr
}

func (f *fakeRepository) RecordAttempt(
	_ context.Context,
	attempt Attempt,
) error {
	if f.record == nil {
		return nil
	}
	return f.record(attempt)
}

type fakePasswordVerifier struct {
	verify func(string, string) (bool, error)
}

func (f *fakePasswordVerifier) Verify(
	password string,
	hash string,
) (bool, error) {
	return f.verify(password, hash)
}

type fakeUUIDGenerator struct {
	values []string
	index  int
}

func (f *fakeUUIDGenerator) GenerateString() (string, error) {
	if f.index >= len(f.values) {
		return "", errors.New("no UUID configured")
	}
	value := f.values[f.index]
	f.index++
	return value, nil
}

type fakeRateLimiter struct{}

func (*fakeRateLimiter) AllowLoginIP(
	context.Context,
	string,
	netip.Addr,
) (bool, error) {
	return true, nil
}

func (*fakeRateLimiter) AllowLoginEmail(
	context.Context,
	string,
	string,
) (bool, error) {
	return true, nil
}

type fakeAccessTokenIssuer struct{}

func (*fakeAccessTokenIssuer) Issue(
	claims AccessTokenClaims,
) (string, time.Time, error) {
	if claims.Subject != testUserID ||
		claims.DeviceID != testDeviceID ||
		claims.JTI != testAccessJTI {
		return "", time.Time{}, errors.New("unexpected claims")
	}
	return "access-token", testNow.Add(time.Hour), nil
}

type fakeRefreshTokenEncoder struct{}

func (*fakeRefreshTokenEncoder) Encode(
	claims appauth.RefreshTokenClaims,
) (string, error) {
	if claims.UserID != testUserID ||
		claims.DeviceID != testDeviceID ||
		claims.TokenID != testRefreshID ||
		!claims.IssuedAt.Equal(testNow) ||
		!claims.ExpiresAt.Equal(testNow.Add(appauth.RefreshTokenTTL)) {
		return "", errors.New("unexpected refresh-token claims")
	}
	return "refresh-token", nil
}

type fakeSessionStore struct {
	save   func(Session) error
	delete func(identity.ID, string) error
}

func (f *fakeSessionStore) Save(
	_ context.Context,
	session Session,
) error {
	if f.save == nil {
		return nil
	}
	return f.save(session)
}

func (f *fakeSessionStore) Delete(
	_ context.Context,
	userID identity.ID,
	deviceID string,
) error {
	if f.delete == nil {
		return nil
	}
	return f.delete(userID, deviceID)
}
