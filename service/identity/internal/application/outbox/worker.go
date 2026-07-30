package outbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	domainlocale "github.com/DoMinhHHung/beexter/service/identity/internal/domain/locale"
	"github.com/google/uuid"
)

const (
	EventEmailVerificationRequested = "identity.email_verification_requested"
	maxBatchSize                    = 100
	maxLastErrorLength              = 1000
)

var (
	ErrDependencyMissing = errors.New(
		"outbox worker dependency is missing",
	)
	ErrInvalidConfig = errors.New(
		"outbox worker configuration is invalid",
	)
	ErrDeliveryNotFound = errors.New(
		"outbox delivery target was not found",
	)
)

type WorkerConfig struct {
	PollInterval    time.Duration
	BatchSize       int
	LockTimeout     time.Duration
	DatabaseTimeout time.Duration
	DeliveryTimeout time.Duration
	RetryBase       time.Duration
	RetryMax        time.Duration
}

type ClaimParams struct {
	LockID      string
	ClaimedAt   time.Time
	StaleBefore time.Time
	Limit       int
	EventTypes  []string
}

type Event struct {
	ID           string
	AggregateID  string
	EventType    string
	Payload      json.RawMessage
	AttemptCount int
}

type VerificationDelivery struct {
	Email     string
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
}

type VerificationMessage struct {
	EventID   string
	Recipient string
	TokenID   string
	ExpiresAt time.Time
	Locale    string
}

type Repository interface {
	Claim(
		ctx context.Context,
		params ClaimParams,
	) ([]Event, error)

	LoadEmailVerification(
		ctx context.Context,
		identityID string,
		tokenID string,
	) (VerificationDelivery, error)

	MarkProcessed(
		ctx context.Context,
		eventID string,
		lockID string,
		processedAt time.Time,
	) error

	Reschedule(
		ctx context.Context,
		eventID string,
		lockID string,
		availableAt time.Time,
		lastError string,
	) error
}

type VerificationMailer interface {
	SendVerification(
		ctx context.Context,
		message VerificationMessage,
	) error
}

type UUIDGenerator interface {
	GenerateString() (string, error)
}

type Worker struct {
	repository Repository
	mailer     VerificationMailer
	ids        UUIDGenerator
	logger     *slog.Logger
	config     WorkerConfig
	now        func() time.Time
}

func NewWorker(
	repository Repository,
	mailer VerificationMailer,
	ids UUIDGenerator,
	logger *slog.Logger,
	config WorkerConfig,
	now func() time.Time,
) (*Worker, error) {
	if repository == nil ||
		mailer == nil ||
		ids == nil ||
		logger == nil ||
		now == nil {
		return nil, ErrDependencyMissing
	}

	if err := validateWorkerConfig(config); err != nil {
		return nil, err
	}

	return &Worker{
		repository: repository,
		mailer:     mailer,
		ids:        ids,
		logger:     logger,
		config:     config,
		now:        now,
	}, nil
}

func (w *Worker) Run(ctx context.Context) {
	if w == nil || ctx == nil {
		return
	}

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-timer.C:
			w.processCycleSafely(ctx)
			timer.Reset(w.config.PollInterval)
		}
	}
}

func (w *Worker) processCycleSafely(ctx context.Context) {
	defer func() {
		panicValue := recover()
		if panicValue == nil {
			return
		}

		w.logger.Error(
			"outbox worker panic recovered",
			slog.Any("panic", panicValue),
			slog.String("stack", string(debug.Stack())),
		)
	}()

	w.processCycle(ctx)
}

func (w *Worker) processCycle(ctx context.Context) {
	lockID, err := w.ids.GenerateString()
	if err != nil {
		w.logger.Error(
			"failed to generate outbox lock ID",
			slog.String("error", err.Error()),
		)
		return
	}

	now := w.now().UTC()
	if now.IsZero() {
		w.logger.Error("outbox worker clock returned zero time")
		return
	}

	claimContext, cancelClaim := context.WithTimeout(
		ctx,
		w.config.DatabaseTimeout,
	)
	defer cancelClaim()

	events, err := w.repository.Claim(
		claimContext,
		ClaimParams{
			LockID:      lockID,
			ClaimedAt:   now,
			StaleBefore: now.Add(-w.config.LockTimeout),
			Limit:       w.config.BatchSize,
			EventTypes: []string{
				EventEmailVerificationRequested,
			},
		},
	)
	if err != nil {
		if ctx.Err() != nil {
			return
		}

		w.logger.Error(
			"failed to claim outbox events",
			slog.String("error", err.Error()),
		)
		return
	}

	for _, event := range events {
		if ctx.Err() != nil {
			return
		}

		w.processEvent(ctx, event, lockID)
	}
}

func (w *Worker) processEvent(
	ctx context.Context,
	event Event,
	lockID string,
) {
	switch event.EventType {
	case EventEmailVerificationRequested:
		w.processEmailVerification(ctx, event, lockID)

	default:
		w.reschedule(
			ctx,
			event,
			lockID,
			fmt.Errorf(
				"unsupported outbox event type %q",
				event.EventType,
			),
		)
	}
}

func (w *Worker) processEmailVerification(
	ctx context.Context,
	event Event,
	lockID string,
) {
	payload, err := decodeVerificationPayload(event.Payload)
	if err != nil {
		w.reschedule(ctx, event, lockID, err)
		return
	}

	loadContext, cancelLoad := context.WithTimeout(
		ctx,
		w.config.DatabaseTimeout,
	)

	delivery, err := w.repository.LoadEmailVerification(
		loadContext,
		payload.IdentityID,
		payload.TokenID,
	)
	cancelLoad()

	if errors.Is(err, ErrDeliveryNotFound) {
		w.markProcessed(ctx, event, lockID)
		return
	}

	if err != nil {
		w.reschedule(
			ctx,
			event,
			lockID,
			fmt.Errorf("load email verification delivery: %w", err),
		)
		return
	}

	now := w.now().UTC()
	if delivery.UsedAt != nil ||
		delivery.RevokedAt != nil ||
		!delivery.ExpiresAt.After(now) {
		w.markProcessed(ctx, event, lockID)
		return
	}

	deliveryContext, cancelDelivery := context.WithTimeout(
		ctx,
		w.config.DeliveryTimeout,
	)

	err = w.mailer.SendVerification(
		deliveryContext,
		VerificationMessage{
			EventID:   event.ID,
			Recipient: delivery.Email,
			TokenID:   payload.TokenID,
			ExpiresAt: delivery.ExpiresAt,
			Locale:    domainlocale.Normalize(payload.Locale),
		},
	)
	cancelDelivery()

	if err != nil {
		w.reschedule(
			ctx,
			event,
			lockID,
			fmt.Errorf("send email verification message: %w", err),
		)
		return
	}

	w.markProcessed(ctx, event, lockID)
}

func (w *Worker) markProcessed(
	ctx context.Context,
	event Event,
	lockID string,
) {
	operationContext, cancelOperation := context.WithTimeout(
		context.WithoutCancel(ctx),
		w.config.DatabaseTimeout,
	)
	defer cancelOperation()

	err := w.repository.MarkProcessed(
		operationContext,
		event.ID,
		lockID,
		w.now().UTC(),
	)
	if err != nil {
		w.logger.Error(
			"failed to mark outbox event as processed",
			slog.String("event_id", event.ID),
			slog.String("error", err.Error()),
		)
		return
	}

	w.logger.Info(
		"outbox event processed",
		slog.String("event_id", event.ID),
		slog.String("event_type", event.EventType),
	)
}

func (w *Worker) reschedule(
	ctx context.Context,
	event Event,
	lockID string,
	cause error,
) {
	failedAttempt := event.AttemptCount + 1
	delay := retryDelay(
		failedAttempt,
		w.config.RetryBase,
		w.config.RetryMax,
	)

	operationContext, cancelOperation := context.WithTimeout(
		context.WithoutCancel(ctx),
		w.config.DatabaseTimeout,
	)
	defer cancelOperation()

	err := w.repository.Reschedule(
		operationContext,
		event.ID,
		lockID,
		w.now().UTC().Add(delay),
		sanitizeError(cause),
	)
	if err != nil {
		w.logger.Error(
			"failed to reschedule outbox event",
			slog.String("event_id", event.ID),
			slog.Int("attempt", failedAttempt),
			slog.String("error", err.Error()),
		)
		return
	}

	w.logger.Warn(
		"outbox event delivery failed",
		slog.String("event_id", event.ID),
		slog.String("event_type", event.EventType),
		slog.Int("attempt", failedAttempt),
		slog.Duration("retry_after", delay),
		slog.String("error", sanitizeError(cause)),
	)
}

type verificationPayload struct {
	IdentityID string `json:"identity_id"`
	TokenID    string `json:"token_id"`
	Locale     string `json:"locale"`
}

func decodeVerificationPayload(
	rawPayload json.RawMessage,
) (verificationPayload, error) {
	decoder := json.NewDecoder(bytes.NewReader(rawPayload))
	decoder.DisallowUnknownFields()

	var payload verificationPayload
	if err := decoder.Decode(&payload); err != nil {
		return verificationPayload{}, fmt.Errorf(
			"decode email verification payload: %w",
			err,
		)
	}

	var trailingValue any
	err := decoder.Decode(&trailingValue)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return verificationPayload{}, errors.New(
				"email verification payload contains multiple JSON values",
			)
		}

		return verificationPayload{}, fmt.Errorf(
			"decode trailing email verification payload: %w",
			err,
		)
	}

	if err := validateUUIDV7(payload.IdentityID); err != nil {
		return verificationPayload{}, fmt.Errorf(
			"validate payload identity ID: %w",
			err,
		)
	}

	if err := validateUUIDV7(payload.TokenID); err != nil {
		return verificationPayload{}, fmt.Errorf(
			"validate payload token ID: %w",
			err,
		)
	}

	payload.Locale = domainlocale.Normalize(payload.Locale)
	return payload, nil
}

func validateUUIDV7(rawID string) error {
	parsedID, err := uuid.Parse(rawID)
	if err != nil {
		return fmt.Errorf("parse UUID: %w", err)
	}

	if parsedID.Version() != 7 ||
		parsedID.Variant() != uuid.RFC4122 ||
		parsedID.String() != rawID {
		return errors.New("UUID must be a canonical version 7 UUID")
	}

	return nil
}

func retryDelay(
	attempt int,
	base time.Duration,
	maximum time.Duration,
) time.Duration {
	if attempt <= 1 {
		return base
	}

	delay := base
	for currentAttempt := 1; currentAttempt < attempt; currentAttempt++ {
		if delay >= maximum || delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}

	if delay > maximum {
		return maximum
	}

	return delay
}

func sanitizeError(err error) string {
	if err == nil {
		return "unknown outbox delivery error"
	}

	message := strings.TrimSpace(err.Error())
	message = strings.NewReplacer("\r", " ", "\n", " ").Replace(message)
	if message == "" {
		return "unknown outbox delivery error"
	}

	runes := []rune(message)
	if len(runes) > maxLastErrorLength {
		runes = runes[:maxLastErrorLength]
	}

	return string(runes)
}

func validateWorkerConfig(config WorkerConfig) error {
	switch {
	case config.PollInterval <= 0:
		return fmt.Errorf(
			"%w: poll interval must be positive",
			ErrInvalidConfig,
		)

	case config.BatchSize <= 0 || config.BatchSize > maxBatchSize:
		return fmt.Errorf(
			"%w: batch size must be between 1 and %d",
			ErrInvalidConfig,
			maxBatchSize,
		)

	case config.LockTimeout <= 0:
		return fmt.Errorf(
			"%w: lock timeout must be positive",
			ErrInvalidConfig,
		)

	case config.DatabaseTimeout <= 0:
		return fmt.Errorf(
			"%w: database timeout must be positive",
			ErrInvalidConfig,
		)

	case config.DeliveryTimeout <= 0:
		return fmt.Errorf(
			"%w: delivery timeout must be positive",
			ErrInvalidConfig,
		)

	case config.RetryBase <= 0:
		return fmt.Errorf(
			"%w: retry base must be positive",
			ErrInvalidConfig,
		)

	case config.RetryMax < config.RetryBase:
		return fmt.Errorf(
			"%w: retry max must not be less than retry base",
			ErrInvalidConfig,
		)
	}

	minimumLockTimeout := time.Duration(config.BatchSize) *
		(config.DeliveryTimeout + 2*config.DatabaseTimeout)
	if config.LockTimeout <= minimumLockTimeout {
		return fmt.Errorf(
			"%w: lock timeout must exceed maximum batch processing time %s",
			ErrInvalidConfig,
			minimumLockTimeout,
		)
	}

	return nil
}
