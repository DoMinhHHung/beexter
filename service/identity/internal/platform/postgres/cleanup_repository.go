package postgres

import (
	"context"
	"errors"
	"fmt"

	appcleanup "github.com/DoMinhHHung/beexter/service/identity/internal/application/cleanup"
	"github.com/jackc/pgx/v5"
)

const deleteOldLoginAttemptsSQL = `
WITH candidates AS (
    SELECT ctid
    FROM identity.login_attempts
    WHERE attempted_at < $1
    ORDER BY attempted_at
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
DELETE FROM identity.login_attempts AS target
USING candidates
WHERE target.ctid = candidates.ctid
`

const deleteExpiredVerificationTokensSQL = `
WITH candidates AS (
    SELECT ctid
    FROM identity.email_verification_tokens
    WHERE expires_at < $1
    ORDER BY expires_at
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
DELETE FROM identity.email_verification_tokens AS target
USING candidates
WHERE target.ctid = candidates.ctid
`

const deleteExpiredPasswordResetTokensSQL = `
WITH candidates AS (
    SELECT ctid
    FROM identity.password_reset_tokens
    WHERE expires_at < $1
    ORDER BY expires_at
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
DELETE FROM identity.password_reset_tokens AS target
USING candidates
WHERE target.ctid = candidates.ctid
`

const deleteProcessedOutboxEventsSQL = `
WITH candidates AS (
    SELECT ctid
    FROM identity.outbox_events
    WHERE processed_at IS NOT NULL
      AND processed_at < $1
    ORDER BY processed_at
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
DELETE FROM identity.outbox_events AS target
USING candidates
WHERE target.ctid = candidates.ctid
`

var (
	ErrCleanupRepositoryNotInitialized = errors.New(
		"cleanup repository is not initialized",
	)
	ErrCleanupRepositoryContextRequired = errors.New(
		"cleanup repository context is required",
	)
)

type CleanupRepository struct {
	database transactionBeginner
}

func NewCleanupRepository(
	database transactionBeginner,
) (*CleanupRepository, error) {
	if database == nil {
		return nil, ErrCleanupRepositoryNotInitialized
	}
	return &CleanupRepository{database: database}, nil
}

func (r *CleanupRepository) Cleanup(
	ctx context.Context,
	params appcleanup.Params,
) (stats appcleanup.Stats, returnErr error) {
	if r == nil || r.database == nil {
		return stats, ErrCleanupRepositoryNotInitialized
	}
	if ctx == nil {
		return stats, ErrCleanupRepositoryContextRequired
	}

	tx, err := r.database.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite},
	)
	if err != nil {
		return stats, fmt.Errorf("begin cleanup transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		rollbackContext, cancelRollback := context.WithTimeout(
			context.WithoutCancel(ctx),
			transactionRollbackTimeout,
		)
		defer cancelRollback()
		rollbackErr := tx.Rollback(rollbackContext)
		if rollbackErr == nil || errors.Is(rollbackErr, pgx.ErrTxClosed) {
			return
		}
		wrapped := fmt.Errorf("rollback cleanup transaction: %w", rollbackErr)
		if returnErr == nil {
			returnErr = wrapped
		} else {
			returnErr = errors.Join(returnErr, wrapped)
		}
	}()

	operations := []struct {
		name      string
		statement string
		cutoff    any
		assign    func(int64)
	}{
		{
			name:      "login attempts",
			statement: deleteOldLoginAttemptsSQL,
			cutoff:    params.LoginAttemptsBefore,
			assign: func(count int64) {
				stats.LoginAttemptsDeleted = count
			},
		},
		{
			name:      "email verification tokens",
			statement: deleteExpiredVerificationTokensSQL,
			cutoff:    params.TokensExpiredBefore,
			assign: func(count int64) {
				stats.VerificationTokensDeleted = count
			},
		},
		{
			name:      "password reset tokens",
			statement: deleteExpiredPasswordResetTokensSQL,
			cutoff:    params.TokensExpiredBefore,
			assign: func(count int64) {
				stats.PasswordResetTokensDeleted = count
			},
		},
		{
			name:      "processed outbox events",
			statement: deleteProcessedOutboxEventsSQL,
			cutoff:    params.OutboxProcessedBefore,
			assign: func(count int64) {
				stats.OutboxEventsDeleted = count
			},
		},
	}

	for _, operation := range operations {
		commandTag, err := tx.Exec(
			ctx,
			operation.statement,
			operation.cutoff,
			params.BatchSize,
		)
		if err != nil {
			return stats, fmt.Errorf("delete old %s: %w", operation.name, err)
		}
		operation.assign(commandTag.RowsAffected())
	}

	if err := tx.Commit(ctx); err != nil {
		return stats, fmt.Errorf("commit cleanup transaction: %w", err)
	}
	committed = true
	return stats, nil
}

var _ appcleanup.Repository = (*CleanupRepository)(nil)
