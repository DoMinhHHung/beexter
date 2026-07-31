package deleteaccount

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

var (
	deleteTestUserID = identity.ID("0198f124-659f-7cbd-a441-dc7eea175073")
	deleteTestNow    = time.Date(2026, time.July, 31, 3, 0, 0, 0, time.UTC)
)

func TestExecuteSoftDeletesAndRevokesSessions(t *testing.T) {
	t.Parallel()

	var revoked bool
	repository := &deleteRepositoryStub{
		credential: Credential{
			PasswordHash:    "hash",
			Status:          identity.StatusActive,
			SoftDeleteCount: 2,
		},
		result: DeleteResult{SoftDeleteCount: 3},
	}
	useCase, err := New(
		repository,
		&deletePasswordStub{matches: true},
		&deleteLimiterStub{allowed: true},
		deleteRevokerFunc(func(_ context.Context, userID identity.ID, cutoff time.Time) error {
			if userID != deleteTestUserID || !cutoff.Equal(deleteTestNow) {
				t.Fatalf("unexpected revocation: %s %s", userID, cutoff)
			}
			revoked = true
			return nil
		}),
		func() time.Time { return deleteTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	output, err := useCase.Execute(context.Background(), validDeleteInput())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !output.Deleted || output.HardDeleted || output.SoftDeleteCount != 3 {
		t.Fatalf("unexpected output: %+v", output)
	}
	if !revoked || repository.deleted == nil {
		t.Fatal("expected session revocation and repository mutation")
	}
	if repository.deleted.ExpectedPasswordHash != "hash" ||
		!repository.deleted.DeletedAt.Equal(deleteTestNow) {
		t.Fatalf("unexpected delete params: %+v", repository.deleted)
	}
}

func TestExecuteWrongPasswordDoesNotMutate(t *testing.T) {
	t.Parallel()

	repository := &deleteRepositoryStub{credential: Credential{
		PasswordHash: "hash",
		Status:       identity.StatusActive,
	}}
	useCase, err := New(
		repository,
		&deletePasswordStub{matches: false},
		&deleteLimiterStub{allowed: true},
		deleteRevokerFunc(func(context.Context, identity.ID, time.Time) error {
			t.Fatal("must not revoke sessions")
			return nil
		}),
		func() time.Time { return deleteTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	_, err = useCase.Execute(context.Background(), validDeleteInput())
	var domainError *domain.Error
	if !errors.As(err, &domainError) || domainError.Code != domain.ErrInvalidCredentials {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	if repository.deleted != nil {
		t.Fatal("repository must not mutate")
	}
}

func TestExecuteFailsClosedWhenRateLimiterErrors(t *testing.T) {
	t.Parallel()

	useCase, err := New(
		&deleteRepositoryStub{},
		&deletePasswordStub{},
		&deleteLimiterStub{err: errors.New("redis down")},
		deleteRevokerFunc(func(context.Context, identity.ID, time.Time) error { return nil }),
		func() time.Time { return deleteTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	_, err = useCase.Execute(context.Background(), validDeleteInput())
	var domainError *domain.Error
	if !errors.As(err, &domainError) || domainError.Code != domain.ErrInternal {
		t.Fatalf("expected internal error, got %v", err)
	}
}

func validDeleteInput() Input {
	return Input{
		UserID:          deleteTestUserID,
		CurrentPassword: "Secure1!",
		IPAddress:       netip.MustParseAddr("192.0.2.10"),
		RequestID:       "request-id",
	}
}

type deleteRepositoryStub struct {
	credential Credential
	loadErr    error
	result     DeleteResult
	deleteErr  error
	deleted    *DeleteParams
}

func (s *deleteRepositoryStub) LoadCredential(context.Context, identity.ID) (Credential, error) {
	return s.credential, s.loadErr
}
func (s *deleteRepositoryStub) DeleteAccount(_ context.Context, params DeleteParams) (DeleteResult, error) {
	s.deleted = &params
	return s.result, s.deleteErr
}

type deletePasswordStub struct {
	matches bool
	err     error
}

func (s *deletePasswordStub) Verify(string, string) (bool, error) { return s.matches, s.err }

type deleteLimiterStub struct {
	allowed bool
	err     error
}

func (s *deleteLimiterStub) AllowDeleteAccountIP(context.Context, string, netip.Addr) (bool, error) {
	return s.allowed, s.err
}
func (s *deleteLimiterStub) AllowDeleteAccountIdentity(context.Context, string, identity.ID) (bool, error) {
	return s.allowed, s.err
}

type deleteRevokerFunc func(context.Context, identity.ID, time.Time) error

func (f deleteRevokerFunc) RevokeCreatedAtOrBefore(ctx context.Context, id identity.ID, cutoff time.Time) error {
	return f(ctx, id, cutoff)
}
