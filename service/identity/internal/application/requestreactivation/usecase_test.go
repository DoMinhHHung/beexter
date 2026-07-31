package requestreactivation

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

var (
	reactivationTestID  = identity.ID("0198f124-659f-7cbd-a441-dc7eea175073")
	reactivationTestNow = time.Date(2026, time.July, 31, 4, 0, 0, 0, time.UTC)
)

func TestExecuteCreatesLocalizedReactivationRequest(t *testing.T) {
	t.Parallel()

	deletedAt := reactivationTestNow.Add(-time.Hour)
	repository := &reactivationRepositoryStub{candidate: Candidate{
		IdentityID:      reactivationTestID,
		PasswordHash:    "real-hash",
		Status:          identity.StatusInactive,
		DeletedAt:       &deletedAt,
		SoftDeleteCount: 1,
	}}
	useCase, err := New(
		repository,
		&reactivationPasswordStub{matchesByHash: map[string]bool{"real-hash": true}},
		&reactivationIDStub{values: []string{
			"0198f124-659f-7cbd-a441-dc7eea175074",
			"0198f124-659f-7cbd-a441-dc7eea175075",
		}},
		&reactivationLimiterStub{allowed: true},
		"dummy-hash",
		func() time.Time { return reactivationTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	output, err := useCase.Execute(context.Background(), validReactivationInput())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !output.Accepted || repository.created == nil {
		t.Fatalf("expected accepted request, got %+v", output)
	}
	if repository.created.Locale != "ja" ||
		repository.created.EventType != verificationEventType ||
		!repository.created.ExpiresAt.Equal(reactivationTestNow.Add(time.Hour)) {
		t.Fatalf("unexpected create params: %+v", repository.created)
	}
}

func TestExecuteUnknownEmailUsesDummyHashAndReturnsGenericSuccess(t *testing.T) {
	t.Parallel()

	passwords := &reactivationPasswordStub{matchesByHash: map[string]bool{"dummy-hash": false}}
	repository := &reactivationRepositoryStub{findErr: ErrIdentityNotFound}
	useCase, err := New(
		repository,
		passwords,
		&reactivationIDStub{},
		&reactivationLimiterStub{allowed: true},
		"dummy-hash",
		func() time.Time { return reactivationTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	output, err := useCase.Execute(context.Background(), validReactivationInput())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !output.Accepted || passwords.lastHash != "dummy-hash" {
		t.Fatalf("expected generic success and dummy hash, output=%+v hash=%q", output, passwords.lastHash)
	}
	if repository.created != nil {
		t.Fatal("must not create token for unknown identity")
	}
}

func TestExecuteStateConflictRemainsGeneric(t *testing.T) {
	t.Parallel()

	deletedAt := reactivationTestNow.Add(-time.Hour)
	repository := &reactivationRepositoryStub{
		candidate: Candidate{
			IdentityID:   reactivationTestID,
			PasswordHash: "real-hash",
			Status:       identity.StatusInactive,
			DeletedAt:    &deletedAt,
		},
		createErr: ErrStateChanged,
	}
	useCase, err := New(
		repository,
		&reactivationPasswordStub{matchesByHash: map[string]bool{"real-hash": true}},
		&reactivationIDStub{values: []string{"a", "b"}},
		&reactivationLimiterStub{allowed: true},
		"dummy-hash",
		func() time.Time { return reactivationTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	output, err := useCase.Execute(context.Background(), validReactivationInput())
	if err != nil || !output.Accepted {
		t.Fatalf("expected generic success, output=%+v err=%v", output, err)
	}
}

func TestExecuteFailsClosedWhenRedisFails(t *testing.T) {
	t.Parallel()

	useCase, err := New(
		&reactivationRepositoryStub{},
		&reactivationPasswordStub{},
		&reactivationIDStub{},
		&reactivationLimiterStub{err: errors.New("redis down")},
		"dummy-hash",
		func() time.Time { return reactivationTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}
	if _, err := useCase.Execute(context.Background(), validReactivationInput()); err == nil {
		t.Fatal("expected fail-closed error")
	}
}

func validReactivationInput() Input {
	return Input{
		Email:     "User@Example.com",
		Password:  "Secure1!",
		Locale:    "ja-JP",
		IPAddress: netip.MustParseAddr("192.0.2.10"),
		RequestID: "request-id",
	}
}

type reactivationRepositoryStub struct {
	candidate Candidate
	findErr   error
	createErr error
	created   *CreateParams
}

func (s *reactivationRepositoryStub) FindByEmail(context.Context, string) (Candidate, error) {
	return s.candidate, s.findErr
}
func (s *reactivationRepositoryStub) Request(_ context.Context, params CreateParams) error {
	s.created = &params
	return s.createErr
}

type reactivationPasswordStub struct {
	matchesByHash map[string]bool
	lastHash      string
}

func (s *reactivationPasswordStub) Verify(_ string, hash string) (bool, error) {
	s.lastHash = hash
	return s.matchesByHash[hash], nil
}

type reactivationIDStub struct {
	values []string
	index  int
}

func (s *reactivationIDStub) GenerateString() (string, error) {
	if s.index >= len(s.values) {
		return "", errors.New("no ID")
	}
	value := s.values[s.index]
	s.index++
	return value, nil
}

type reactivationLimiterStub struct {
	allowed bool
	err     error
}

func (s *reactivationLimiterStub) AllowReactivationIP(context.Context, string, netip.Addr) (bool, error) {
	return s.allowed, s.err
}
func (s *reactivationLimiterStub) AllowReactivationEmail(context.Context, string, string) (bool, error) {
	return s.allowed, s.err
}
