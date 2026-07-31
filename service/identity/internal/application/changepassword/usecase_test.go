package changepassword

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

const changePasswordTestUserID = identity.ID(
	"0198f124-659f-7cbd-a441-dc7eea175073",
)

var changePasswordTestNow = time.Date(
	2026, time.July, 31, 2, 0, 0, 0, time.UTC,
)

func TestUseCaseChangesPasswordAndRevokesSessions(t *testing.T) {
	t.Parallel()

	repository := &stubRepository{
		credential: Credential{
			PasswordHash: "current-hash",
			Status:       identity.StatusActive,
		},
	}
	revoker := &stubRevoker{}
	useCase, err := New(
		repository,
		&stubHasher{},
		allowingRateLimiter{},
		revoker,
		func() time.Time { return changePasswordTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	output, err := useCase.Execute(
		context.Background(),
		validInput(),
	)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !output.PasswordChanged {
		t.Fatal("expected password_changed=true")
	}
	if !revoker.called || revoker.cutoff != changePasswordTestNow {
		t.Fatalf("unexpected revocation: %+v", revoker)
	}
	if repository.changed == nil {
		t.Fatal("expected repository update")
	}
	if repository.changed.ExpectedPasswordHash != "current-hash" ||
		repository.changed.NewPasswordHash != "new-hash" {
		t.Fatalf("unexpected change params: %+v", repository.changed)
	}
}

func TestUseCaseRejectsWrongCurrentPassword(t *testing.T) {
	t.Parallel()

	useCase, err := New(
		&stubRepository{
			credential: Credential{
				PasswordHash: "different-hash",
				Status:       identity.StatusActive,
			},
		},
		&stubHasher{},
		allowingRateLimiter{},
		&stubRevoker{},
		func() time.Time { return changePasswordTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	_, err = useCase.Execute(context.Background(), validInput())
	assertDomainCode(t, err, domain.ErrInvalidCredentials)
}

func TestUseCaseRejectsSamePassword(t *testing.T) {
	t.Parallel()

	input := validInput()
	input.NewPassword = input.CurrentPassword
	useCase, err := New(
		&stubRepository{
			credential: Credential{
				PasswordHash: "current-hash",
				Status:       identity.StatusActive,
			},
		},
		&stubHasher{},
		allowingRateLimiter{},
		&stubRevoker{},
		func() time.Time { return changePasswordTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	_, err = useCase.Execute(context.Background(), input)
	assertDomainCode(t, err, domain.ErrInvalidInput)
}

func TestUseCaseFailsClosedWhenRedisFails(t *testing.T) {
	t.Parallel()

	repository := &stubRepository{
		credential: Credential{
			PasswordHash: "current-hash",
			Status:       identity.StatusActive,
		},
	}
	useCase, err := New(
		repository,
		&stubHasher{},
		allowingRateLimiter{},
		&stubRevoker{err: errors.New("redis unavailable")},
		func() time.Time { return changePasswordTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	_, err = useCase.Execute(context.Background(), validInput())
	assertDomainCode(t, err, domain.ErrInternal)
	if repository.changed != nil {
		t.Fatal("database password must not change when Redis revocation fails")
	}
}

func validInput() Input {
	return Input{
		UserID:          changePasswordTestUserID,
		CurrentPassword: "Secure1!",
		NewPassword:     "Secure2!",
		IPAddress:       netip.MustParseAddr("192.0.2.10"),
		RequestID:       "request-1",
	}
}

type stubRepository struct {
	credential Credential
	loadErr    error
	changeErr  error
	changed    *ChangeParams
}

func (s *stubRepository) LoadCredential(
	context.Context,
	identity.ID,
) (Credential, error) {
	return s.credential, s.loadErr
}

func (s *stubRepository) ChangePassword(
	_ context.Context,
	params ChangeParams,
) error {
	copy := params
	s.changed = &copy
	return s.changeErr
}

type stubHasher struct{}

func (*stubHasher) Hash(password string) (string, error) {
	if password == "Secure2!" {
		return "new-hash", nil
	}
	return "", errors.New("unexpected password")
}

func (*stubHasher) Verify(password string, encodedHash string) (bool, error) {
	switch password {
	case "Secure1!":
		return encodedHash == "current-hash", nil
	case "Secure2!":
		return encodedHash == "new-hash", nil
	default:
		return false, nil
	}
}

type allowingRateLimiter struct{}

func (allowingRateLimiter) AllowChangePasswordIP(
	context.Context,
	string,
	netip.Addr,
) (bool, error) {
	return true, nil
}

func (allowingRateLimiter) AllowChangePasswordIdentity(
	context.Context,
	string,
	identity.ID,
) (bool, error) {
	return true, nil
}

type stubRevoker struct {
	called bool
	cutoff time.Time
	err    error
}

func (s *stubRevoker) RevokeCreatedAtOrBefore(
	_ context.Context,
	_ identity.ID,
	cutoff time.Time,
) error {
	s.called = true
	s.cutoff = cutoff
	return s.err
}

func assertDomainCode(t *testing.T, err error, expected domain.ErrorCode) {
	t.Helper()
	var domainError *domain.Error
	if !errors.As(err, &domainError) {
		t.Fatalf("expected domain error, got %v", err)
	}
	if domainError.Code != expected {
		t.Fatalf("expected %s, got %s", expected, domainError.Code)
	}
}
