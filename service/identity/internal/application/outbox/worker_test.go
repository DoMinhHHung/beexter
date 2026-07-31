package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	testEventID    = "0198f124-659f-7cbd-a441-dc7eea175073"
	testIdentityID = "0198f124-659f-7cbd-a441-dc7eea175074"
	testTokenID    = "0198f124-659f-7cbd-a441-dc7eea175075"
	testLockID     = "0198f124-659f-7cbd-a441-dc7eea175076"
)

var workerTestNow = time.Date(
	2026,
	time.July,
	30,
	8,
	0,
	0,
	0,
	time.UTC,
)

func TestWorkerProcessesVerificationEvent(t *testing.T) {
	t.Parallel()

	repository := &fakeRepository{
		events: []Event{validTokenEmailEvent(
			EventEmailVerificationRequested,
			0,
		)},
		verificationDelivery: VerificationDelivery{
			Email:     "user@example.com",
			ExpiresAt: workerTestNow.Add(time.Hour),
		},
	}

	worker := newTestWorker(
		t,
		repository,
		&fakeVerificationMailer{
			send: func(
				_ context.Context,
				message VerificationMessage,
			) error {
				if message.Recipient != "user@example.com" {
					t.Fatalf("unexpected recipient %q", message.Recipient)
				}
				if message.Locale != "ja" {
					t.Fatalf("expected locale ja, got %q", message.Locale)
				}
				return nil
			},
		},
		&fakePasswordResetMailer{},
		&fakeSessionRevoker{},
	)
	worker.processCycle(context.Background())

	if !repository.marked {
		t.Fatal("expected event to be marked processed")
	}
	if repository.rescheduled {
		t.Fatal("successful event must not be rescheduled")
	}
}

func TestWorkerProcessesPasswordResetEvent(t *testing.T) {
	t.Parallel()

	repository := &fakeRepository{
		events: []Event{validTokenEmailEvent(
			EventPasswordResetRequested,
			0,
		)},
		passwordResetDelivery: PasswordResetDelivery{
			Email:     "user@example.com",
			ExpiresAt: workerTestNow.Add(time.Hour),
		},
	}

	resetMailerCalled := false
	worker := newTestWorker(
		t,
		repository,
		&fakeVerificationMailer{},
		&fakePasswordResetMailer{
			send: func(
				_ context.Context,
				message PasswordResetMessage,
			) error {
				resetMailerCalled = true
				if message.TokenID != testTokenID {
					t.Fatalf("unexpected token ID %q", message.TokenID)
				}
				if message.Locale != "ja" {
					t.Fatalf("expected locale ja, got %q", message.Locale)
				}
				return nil
			},
		},
		&fakeSessionRevoker{},
	)
	worker.processCycle(context.Background())

	if !resetMailerCalled {
		t.Fatal("expected password-reset mailer call")
	}
	if !repository.marked {
		t.Fatal("expected event to be marked processed")
	}
}

func TestWorkerProcessesRefreshSessionsRevocationEvent(
	t *testing.T,
) {
	t.Parallel()

	repository := &fakeRepository{
		events: []Event{validSessionRevocationEvent(0)},
	}

	revokerCalled := false
	worker := newTestWorker(
		t,
		repository,
		&fakeVerificationMailer{},
		&fakePasswordResetMailer{},
		&fakeSessionRevoker{
			revokeCreatedAtOrBefore: func(
				_ context.Context,
				userID identity.ID,
				cutoff time.Time,
			) error {
				revokerCalled = true
				if userID.String() != testIdentityID {
					t.Fatalf("unexpected user ID %q", userID)
				}
				if !cutoff.Equal(workerTestNow) {
					t.Fatalf("unexpected cutoff %s", cutoff)
				}
				return nil
			},
		},
	)
	worker.processCycle(context.Background())

	if !revokerCalled {
		t.Fatal("expected session revoker call")
	}
	if !repository.marked {
		t.Fatal("expected event to be marked processed")
	}
}

func TestWorkerReschedulesFailedSessionRevocation(t *testing.T) {
	t.Parallel()

	repository := &fakeRepository{
		events: []Event{validSessionRevocationEvent(1)},
	}

	worker := newTestWorker(
		t,
		repository,
		&fakeVerificationMailer{},
		&fakePasswordResetMailer{},
		&fakeSessionRevoker{
			revokeCreatedAtOrBefore: func(
				context.Context,
				identity.ID,
				time.Time,
			) error {
				return errors.New("redis unavailable")
			},
		},
	)
	worker.processCycle(context.Background())

	if !repository.rescheduled {
		t.Fatal("expected event to be rescheduled")
	}
	expectedAvailableAt := workerTestNow.Add(10 * time.Second)
	if !repository.availableAt.Equal(expectedAvailableAt) {
		t.Fatalf(
			"expected available_at %s, got %s",
			expectedAvailableAt,
			repository.availableAt,
		)
	}
	if repository.lastError == "" {
		t.Fatal("expected last error")
	}
}

func TestWorkerReschedulesFailedPasswordResetDelivery(t *testing.T) {
	t.Parallel()

	repository := &fakeRepository{
		events: []Event{validTokenEmailEvent(
			EventPasswordResetRequested,
			1,
		)},
		passwordResetDelivery: PasswordResetDelivery{
			Email:     "user@example.com",
			ExpiresAt: workerTestNow.Add(time.Hour),
		},
	}

	worker := newTestWorker(
		t,
		repository,
		&fakeVerificationMailer{},
		&fakePasswordResetMailer{
			send: func(context.Context, PasswordResetMessage) error {
				return errors.New("SMTP unavailable")
			},
		},
		&fakeSessionRevoker{},
	)
	worker.processCycle(context.Background())

	if !repository.rescheduled {
		t.Fatal("expected event to be rescheduled")
	}
}

func TestWorkerSkipsRevokedPasswordResetToken(t *testing.T) {
	t.Parallel()

	revokedAt := workerTestNow
	repository := &fakeRepository{
		events: []Event{validTokenEmailEvent(
			EventPasswordResetRequested,
			0,
		)},
		passwordResetDelivery: PasswordResetDelivery{
			Email:     "user@example.com",
			ExpiresAt: workerTestNow.Add(time.Hour),
			RevokedAt: &revokedAt,
		},
	}

	worker := newTestWorker(
		t,
		repository,
		&fakeVerificationMailer{},
		&fakePasswordResetMailer{
			send: func(context.Context, PasswordResetMessage) error {
				t.Fatal("mailer must not be called for revoked token")
				return nil
			},
		},
		&fakeSessionRevoker{},
	)
	worker.processCycle(context.Background())

	if !repository.marked {
		t.Fatal("obsolete event should be marked processed")
	}
}

func TestRetryDelayIsCapped(t *testing.T) {
	t.Parallel()

	if delay := retryDelay(20, 5*time.Second, time.Hour); delay != time.Hour {
		t.Fatalf("expected capped delay %s, got %s", time.Hour, delay)
	}
}

func newTestWorker(
	t *testing.T,
	repository Repository,
	verificationMailer VerificationMailer,
	passwordResetMailer PasswordResetMailer,
	sessionRevoker SessionRevoker,
) *Worker {
	t.Helper()

	worker, err := NewWorker(
		repository,
		verificationMailer,
		passwordResetMailer,
		sessionRevoker,
		&fixedUUIDGenerator{value: testLockID},
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
		WorkerConfig{
			PollInterval:    time.Second,
			BatchSize:       1,
			LockTimeout:     time.Minute,
			DatabaseTimeout: time.Second,
			DeliveryTimeout: 5 * time.Second,
			RetryBase:       5 * time.Second,
			RetryMax:        time.Hour,
		},
		func() time.Time { return workerTestNow },
	)
	if err != nil {
		t.Fatalf("create worker: %v", err)
	}
	return worker
}

func validTokenEmailEvent(eventType string, attemptCount int) Event {
	payload, err := json.Marshal(map[string]string{
		"identity_id": testIdentityID,
		"token_id":    testTokenID,
		"locale":      "JA-jp",
	})
	if err != nil {
		panic(err)
	}

	return Event{
		ID:           testEventID,
		AggregateID:  testIdentityID,
		EventType:    eventType,
		Payload:      payload,
		AttemptCount: attemptCount,
	}
}

func validSessionRevocationEvent(attemptCount int) Event {
	payload, err := json.Marshal(map[string]string{
		"identity_id":    testIdentityID,
		"token_id":       testTokenID,
		"phase":          passwordResetPhaseSessionRevocation,
		"session_cutoff": workerTestNow.Format(time.RFC3339),
	})
	if err != nil {
		panic(err)
	}

	return Event{
		ID:           testEventID,
		AggregateID:  testIdentityID,
		EventType:    EventPasswordResetRequested,
		Payload:      payload,
		AttemptCount: attemptCount,
	}
}

type fakeRepository struct {
	events                 []Event
	verificationDelivery   VerificationDelivery
	passwordResetDelivery  PasswordResetDelivery
	loadVerificationError  error
	loadPasswordResetError error
	rescheduled            bool
	marked                 bool
	availableAt            time.Time
	lastError              string
}

func (f *fakeRepository) Claim(
	context.Context,
	ClaimParams,
) ([]Event, error) {
	return f.events, nil
}

func (f *fakeRepository) LoadEmailVerification(
	context.Context,
	string,
	string,
) (VerificationDelivery, error) {
	return f.verificationDelivery, f.loadVerificationError
}

func (f *fakeRepository) LoadPasswordReset(
	context.Context,
	string,
	string,
) (PasswordResetDelivery, error) {
	return f.passwordResetDelivery, f.loadPasswordResetError
}

func (f *fakeRepository) MarkProcessed(
	context.Context,
	string,
	string,
	time.Time,
) error {
	f.marked = true
	return nil
}

func (f *fakeRepository) Reschedule(
	_ context.Context,
	_ string,
	_ string,
	availableAt time.Time,
	lastError string,
) error {
	f.rescheduled = true
	f.availableAt = availableAt
	f.lastError = lastError
	return nil
}

type fakeVerificationMailer struct {
	send func(context.Context, VerificationMessage) error
}

func (f *fakeVerificationMailer) SendVerification(
	ctx context.Context,
	message VerificationMessage,
) error {
	if f.send == nil {
		return nil
	}
	return f.send(ctx, message)
}

type fakePasswordResetMailer struct {
	send func(context.Context, PasswordResetMessage) error
}

func (f *fakePasswordResetMailer) SendPasswordReset(
	ctx context.Context,
	message PasswordResetMessage,
) error {
	if f.send == nil {
		return nil
	}
	return f.send(ctx, message)
}

type fakeSessionRevoker struct {
	revokeCreatedAtOrBefore func(
		context.Context,
		identity.ID,
		time.Time,
	) error
}

func (f *fakeSessionRevoker) RevokeCreatedAtOrBefore(
	ctx context.Context,
	userID identity.ID,
	cutoff time.Time,
) error {
	if f.revokeCreatedAtOrBefore == nil {
		return nil
	}
	return f.revokeCreatedAtOrBefore(ctx, userID, cutoff)
}

type fixedUUIDGenerator struct {
	value string
}

func (g *fixedUUIDGenerator) GenerateString() (string, error) {
	return g.value, nil
}
