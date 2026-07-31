package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appoutbox "github.com/DoMinhHHung/beexter/service/identity/internal/application/outbox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const claimOutboxEventsSQL = `
WITH candidates AS (
    SELECT id
    FROM identity.outbox_events
    WHERE processed_at IS NULL
      AND available_at <= $1
      AND (
          locked_at IS NULL
          OR locked_at < $2
      )
      AND event_type = ANY($5::text[])
    ORDER BY available_at, created_at
    FOR UPDATE SKIP LOCKED
    LIMIT $3
)
UPDATE identity.outbox_events AS event
SET
    locked_at = $1,
    lock_id = $4
FROM candidates
WHERE event.id = candidates.id
RETURNING
    event.id::text,
    event.aggregate_id::text,
    event.event_type,
    event.payload,
    event.attempt_count
`

const loadEmailVerificationDeliverySQL = `
SELECT
    identity.email,
    token.expires_at,
    token.used_at,
    token.revoked_at
FROM identity.email_verification_tokens AS token
JOIN identity.identities AS identity
    ON identity.id = token.identity_id
WHERE identity.id = $1::uuid
  AND token.id = $2::uuid
`

const markOutboxProcessedSQL = `
WITH updated AS (
    UPDATE identity.outbox_events
    SET
        processed_at = $3,
        locked_at = NULL,
        lock_id = NULL,
        last_error = NULL
    WHERE id = $1::uuid
      AND lock_id = $2::uuid
      AND processed_at IS NULL
    RETURNING 1
)
SELECT
    EXISTS (
        SELECT 1
        FROM updated
    )
    OR EXISTS (
        SELECT 1
        FROM identity.outbox_events
        WHERE id = $1::uuid
          AND processed_at IS NOT NULL
    )
`

const rescheduleOutboxEventSQL = `
UPDATE identity.outbox_events
SET
    attempt_count = attempt_count + 1,
    available_at = $3,
    locked_at = NULL,
    lock_id = NULL,
    last_error = $4
WHERE id = $1::uuid
  AND lock_id = $2::uuid
  AND processed_at IS NULL
`

var (
	ErrOutboxRepositoryNotInitialized = errors.New(
		"outbox repository is not initialized",
	)

	ErrOutboxRepositoryContextRequired = errors.New(
		"outbox repository context is required",
	)

	ErrOutboxLockLost = errors.New(
		"outbox event lock was lost",
	)
)

type outboxDatabase interface {
	Query(
		ctx context.Context,
		sql string,
		args ...any,
	) (pgx.Rows, error)

	QueryRow(
		ctx context.Context,
		sql string,
		args ...any,
	) pgx.Row

	Exec(
		ctx context.Context,
		sql string,
		args ...any,
	) (pgconn.CommandTag, error)
}

type OutboxRepository struct {
	database outboxDatabase
}

func NewOutboxRepository(
	database outboxDatabase,
) (*OutboxRepository, error) {
	if database == nil {
		return nil, ErrOutboxRepositoryNotInitialized
	}

	return &OutboxRepository{
		database: database,
	}, nil
}

func (r *OutboxRepository) Claim(
	ctx context.Context,
	params appoutbox.ClaimParams,
) ([]appoutbox.Event, error) {
	if r == nil || r.database == nil {
		return nil, ErrOutboxRepositoryNotInitialized
	}

	if ctx == nil {
		return nil, ErrOutboxRepositoryContextRequired
	}

	rows, err := r.database.Query(
		ctx,
		claimOutboxEventsSQL,
		params.ClaimedAt,
		params.StaleBefore,
		params.Limit,
		params.LockID,
		params.EventTypes,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"claim outbox events: %w",
			err,
		)
	}
	defer rows.Close()

	events := make([]appoutbox.Event, 0, params.Limit)

	for rows.Next() {
		var (
			event      appoutbox.Event
			rawPayload []byte
		)

		if err := rows.Scan(
			&event.ID,
			&event.AggregateID,
			&event.EventType,
			&rawPayload,
			&event.AttemptCount,
		); err != nil {
			return nil, fmt.Errorf(
				"scan claimed outbox event: %w",
				err,
			)
		}

		event.Payload = append(
			json.RawMessage(nil),
			rawPayload...,
		)

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate claimed outbox events: %w",
			err,
		)
	}

	return events, nil
}

func (r *OutboxRepository) LoadEmailVerification(
	ctx context.Context,
	identityID string,
	tokenID string,
) (appoutbox.VerificationDelivery, error) {
	if r == nil || r.database == nil {
		return appoutbox.VerificationDelivery{},
			ErrOutboxRepositoryNotInitialized
	}

	if ctx == nil {
		return appoutbox.VerificationDelivery{},
			ErrOutboxRepositoryContextRequired
	}

	var delivery appoutbox.VerificationDelivery

	err := r.database.QueryRow(
		ctx,
		loadEmailVerificationDeliverySQL,
		identityID,
		tokenID,
	).Scan(
		&delivery.Email,
		&delivery.ExpiresAt,
		&delivery.UsedAt,
		&delivery.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return appoutbox.VerificationDelivery{},
			appoutbox.ErrDeliveryNotFound
	}

	if err != nil {
		return appoutbox.VerificationDelivery{}, fmt.Errorf(
			"load email verification delivery: %w",
			err,
		)
	}

	return delivery, nil
}

func (r *OutboxRepository) MarkProcessed(
	ctx context.Context,
	eventID string,
	lockID string,
	processedAt time.Time,
) error {
	if r == nil || r.database == nil {
		return ErrOutboxRepositoryNotInitialized
	}

	if ctx == nil {
		return ErrOutboxRepositoryContextRequired
	}

	var processed bool

	if err := r.database.QueryRow(
		ctx,
		markOutboxProcessedSQL,
		eventID,
		lockID,
		processedAt,
	).Scan(&processed); err != nil {
		return fmt.Errorf(
			"mark outbox event as processed: %w",
			err,
		)
	}

	if !processed {
		return ErrOutboxLockLost
	}

	return nil
}

func (r *OutboxRepository) Reschedule(
	ctx context.Context,
	eventID string,
	lockID string,
	availableAt time.Time,
	lastError string,
) error {
	if r == nil || r.database == nil {
		return ErrOutboxRepositoryNotInitialized
	}

	if ctx == nil {
		return ErrOutboxRepositoryContextRequired
	}

	commandTag, err := r.database.Exec(
		ctx,
		rescheduleOutboxEventSQL,
		eventID,
		lockID,
		availableAt,
		lastError,
	)
	if err != nil {
		return fmt.Errorf(
			"reschedule outbox event: %w",
			err,
		)
	}

	if commandTag.RowsAffected() != 1 {
		return ErrOutboxLockLost
	}

	return nil
}

var _ appoutbox.Repository = (*OutboxRepository)(nil)
