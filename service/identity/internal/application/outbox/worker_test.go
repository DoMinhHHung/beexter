package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

const (
	testEventID = "0198f124-659f-7cbd-a441-dc7eea175073"

	testIdentityID = "0198f124-659f-7cbd-a441-dc7eea175074"

	testTokenID = "0198f124-659f-7cbd-a441-dc7eea175075"

	testLockID = "0198f124-659f-7cbd-a441-dc7eea175076"
)

var workerTestNow = time.Date(
	2026,
	time.July,
	30,
	3,
	0,
	0,
	0,
	time.UTC,
)

func TestWorkerProcessesVerificationEvent(t *testing.T) {
	t.Parallel()

	var (
		mailerCalled bool
		marked       bool
	)

	repository := &fakeRepository{
		events: []Event{
			validVerificationEvent(0),
		},
		delivery: VerificationDelivery{
			Email: "user@example.com",
			ExpiresAt: workerTestNow.Add(
				time.Hour,
			),
		},
		markProcessed: func(
			_ context.Context,
			eventID string,
			lockID string,
			_ time.Time,
		) error {
			marked = true

			if eventID != testEventID {
				t.Fatalf(
					"unexpected event ID %q",
					eventID,
				)
			}

			if lockID != testLockID {
				t.Fatalf(
					"unexpected lock ID %q",
					lockID,
				)
			}

			return nil
		},
	}

	mailer := &fakeMailer{
		send: func(
			_ context.Context,
			message VerificationMessage,
		) error {
			mailerCalled = true

			if message.Recipient != "user@example.com" {
				t.Fatalf(
					"unexpected recipient %q",
					message.Recipient,
				)
			}

			if message.TokenID != testTokenID {
				t.Fatalf(
					"unexpected token ID %q",
					message.TokenID,
				)
			}

			return nil
		},
	}

	worker := newTestWorker(t, repository, mailer)

	worker.processCycle(context.Background())

	if !mailerCalled {
		t.Fatal("expected verification mailer call")
	}

	if !marked {
		t.Fatal("expected event to be marked processed")
	}

	if repository.rescheduled {
		t.Fatal("successful event must not be rescheduled")
	}
}

func TestWorkerReschedulesFailedDelivery(t *testing.T) {
	t.Parallel()

	repository := &fakeRepository{
		events: []Event{
			validVerificationEvent(1),
		},
		delivery: VerificationDelivery{
			Email: "user@example.com",
			ExpiresAt: workerTestNow.Add(
				time.Hour,
			),
		},
	}

	mailer := &fakeMailer{
		send: func(
			context.Context,
			VerificationMessage,
		) error {
			return errors.New("SMTP unavailable")
		},
	}

	worker := newTestWorker(t, repository, mailer)

	worker.processCycle(context.Background())

	if !repository.rescheduled {
		t.Fatal("expected event to be rescheduled")
	}

	expectedAvailableAt := workerTestNow.Add(
		10 * time.Second,
	)

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

func TestWorkerSkipsUsedVerificationToken(t *testing.T) {
	t.Parallel()

	usedAt := workerTestNow

	repository := &fakeRepository{
		events: []Event{
			validVerificationEvent(0),
		},
		delivery: VerificationDelivery{
			Email:     "user@example.com",
			ExpiresAt: workerTestNow.Add(time.Hour),
			UsedAt:    &usedAt,
		},
	}

	mailer := &fakeMailer{
		send: func(
			context.Context,
			VerificationMessage,
		) error {
			t.Fatal(
				"mailer must not be called for used token",
			)

			return nil
		},
	}

	worker := newTestWorker(t, repository, mailer)

	worker.processCycle(context.Background())

	if !repository.marked {
		t.Fatal(
			"obsolete event should be marked processed",
		)
	}
}

func TestRetryDelayIsCapped(t *testing.T) {
	t.Parallel()

	delay := retryDelay(
		20,
		5*time.Second,
		time.Hour,
	)

	if delay != time.Hour {
		t.Fatalf(
			"expected capped delay %s, got %s",
			time.Hour,
			delay,
		)
	}
}

func newTestWorker(
	t *testing.T,
	repository Repository,
	mailer VerificationMailer,
) *Worker {
	t.Helper()

	worker, err := NewWorker(
		repository,
		mailer,
		&fixedUUIDGenerator{
			value: testLockID,
		},
		slog.New(
			slog.NewJSONHandler(io.Discard, nil),
		),
		WorkerConfig{
			PollInterval:    time.Second,
			BatchSize:       1,
			LockTimeout:     time.Minute,
			DatabaseTimeout: time.Second,
			DeliveryTimeout: 5 * time.Second,
			RetryBase:       5 * time.Second,
			RetryMax:        time.Hour,
		},
		func() time.Time {
			return workerTestNow
		},
	)
	if err != nil {
		t.Fatalf("create worker: %v", err)
	}

	return worker
}

func validVerificationEvent(
	attemptCount int,
) Event {
	payload, err := json.Marshal(map[string]string{
		"identity_id": testIdentityID,
		"token_id":    testTokenID,
	})
	if err != nil {
		panic(err)
	}

	return Event{
		ID:           testEventID,
		AggregateID:  testIdentityID,
		EventType:    EventEmailVerificationRequested,
		Payload:      payload,
		AttemptCount: attemptCount,
	}
}

type fakeRepository struct {
	events      []Event
	delivery    VerificationDelivery
	loadError   error
	rescheduled bool
	marked      bool
	availableAt time.Time
	lastError   string

	markProcessed func(
		context.Context,
		string,
		string,
		time.Time,
	) error
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
	return f.delivery, f.loadError
}

func (f *fakeRepository) MarkProcessed(
	ctx context.Context,
	eventID string,
	lockID string,
	processedAt time.Time,
) error {
	f.marked = true

	if f.markProcessed != nil {
		return f.markProcessed(
			ctx,
			eventID,
			lockID,
			processedAt,
		)
	}

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

type fakeMailer struct {
	send func(
		context.Context,
		VerificationMessage,
	) error
}

func (f *fakeMailer) SendVerification(
	ctx context.Context,
	message VerificationMessage,
) error {
	return f.send(ctx, message)
}

type fixedUUIDGenerator struct {
	value string
}

func (g *fixedUUIDGenerator) GenerateString() (
	string,
	error,
) {
	return g.value, nil
}
