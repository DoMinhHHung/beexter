package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appresendverification "github.com/DoMinhHHung/beexter/service/identity/internal/application/resendverification"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const selectIdentityForVerificationResendSQL = `
SELECT
    id::text,
    email_verified_at,
    status,
    deleted_at
FROM identity.identities
WHERE email = $1
FOR UPDATE
`

const clearSoftDeletedEmailVerificationSQL = `
UPDATE identity.identities
SET
    email_verified_at = NULL,
    updated_at = $2
WHERE id = $1::uuid
  AND status = 'inactive'
  AND deleted_at IS NOT NULL
`

const revokeActiveEmailVerificationTokensSQL = `
UPDATE identity.email_verification_tokens
SET revoked_at = $2
WHERE identity_id = $1::uuid
  AND used_at IS NULL
  AND revoked_at IS NULL
`

const insertResentVerificationTokenSQL = `
INSERT INTO identity.email_verification_tokens (
    id,
    identity_id,
    expires_at,
    created_at
)
VALUES ($1, $2, $3, $4)
`

const insertResendVerificationOutboxSQL = `
INSERT INTO identity.outbox_events (
    id,
    aggregate_id,
    event_type,
    payload,
    available_at,
    created_at
)
VALUES ($1, $2, $3, $4, $5, $5)
`

var (
	ErrResendVerificationRepositoryNotInitialized = errors.New(
		"resend-verification repository is not initialized",
	)

	ErrResendVerificationRepositoryContextRequired = errors.New(
		"resend-verification repository context is required",
	)

	ErrResendVerificationStateConflict = errors.New(
		"resend-verification state changed unexpectedly",
	)
)

type ResendVerificationRepository struct {
	database transactionBeginner
}

func NewResendVerificationRepository(
	database transactionBeginner,
) (*ResendVerificationRepository, error) {
	if database == nil {
		return nil,
			ErrResendVerificationRepositoryNotInitialized
	}

	return &ResendVerificationRepository{
		database: database,
	}, nil
}

func (r *ResendVerificationRepository) Resend(
	ctx context.Context,
	params appresendverification.CreateParams,
) (returnErr error) {
	if r == nil || r.database == nil {
		return ErrResendVerificationRepositoryNotInitialized
	}

	if ctx == nil {
		return ErrResendVerificationRepositoryContextRequired
	}

	tx, err := r.database.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.ReadCommitted,
			AccessMode: pgx.ReadWrite,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"begin resend-verification transaction: %w",
			err,
		)
	}

	committed := false

	defer func() {
		if committed {
			return
		}

		rollbackContext, cancelRollback :=
			context.WithTimeout(
				context.WithoutCancel(ctx),
				transactionRollbackTimeout,
			)
		defer cancelRollback()

		rollbackErr := tx.Rollback(rollbackContext)
		if rollbackErr == nil ||
			errors.Is(
				rollbackErr,
				pgx.ErrTxClosed,
			) {
			return
		}

		wrappedRollbackError := fmt.Errorf(
			"rollback resend-verification transaction: %w",
			rollbackErr,
		)

		if returnErr == nil {
			returnErr = wrappedRollbackError
			return
		}

		returnErr = errors.Join(
			returnErr,
			wrappedRollbackError,
		)
	}()

	var (
		rawIdentityID   string
		emailVerifiedAt *time.Time
		status          string
		deletedAt       *time.Time
	)

	err = tx.QueryRow(
		ctx,
		selectIdentityForVerificationResendSQL,
		params.Email,
	).Scan(
		&rawIdentityID,
		&emailVerifiedAt,
		&status,
		&deletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}

	if err != nil {
		return fmt.Errorf(
			"select identity for verification resend: %w",
			err,
		)
	}

	identityID, err := identity.ParseID(rawIdentityID)
	if err != nil {
		return fmt.Errorf(
			"parse resend-verification identity ID: %w",
			err,
		)
	}

	standardUnverified :=
		status == string(identity.StatusActive) &&
			deletedAt == nil &&
			emailVerifiedAt == nil

	softDeleted :=
		status == string(identity.StatusInactive) &&
			deletedAt != nil

	if !standardUnverified && !softDeleted {
		return nil
	}

	if softDeleted {
		commandTag, err := tx.Exec(
			ctx,
			clearSoftDeletedEmailVerificationSQL,
			identityID.String(),
			params.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf(
				"clear soft-deleted email verification state: %w",
				err,
			)
		}

		if commandTag.RowsAffected() != 1 {
			return ErrResendVerificationStateConflict
		}
	}

	_, err = tx.Exec(
		ctx,
		revokeActiveEmailVerificationTokensSQL,
		identityID.String(),
		params.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf(
			"revoke active email verification tokens: %w",
			err,
		)
	}

	_, err = tx.Exec(
		ctx,
		insertResentVerificationTokenSQL,
		params.VerificationTokenID,
		identityID.String(),
		params.VerificationTokenExpiresAt,
		params.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf(
			"insert resent email verification token: %w",
			err,
		)
	}

	payload, err := json.Marshal(struct {
		IdentityID string `json:"identity_id"`
		TokenID    string `json:"token_id"`
	}{
		IdentityID: identityID.String(),
		TokenID:    params.VerificationTokenID,
	})
	if err != nil {
		return fmt.Errorf(
			"marshal verification resend outbox payload: %w",
			err,
		)
	}

	_, err = tx.Exec(
		ctx,
		insertResendVerificationOutboxSQL,
		params.OutboxEventID,
		identityID.String(),
		params.OutboxEventType,
		json.RawMessage(payload),
		params.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf(
			"insert verification resend outbox event: %w",
			err,
		)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit resend-verification transaction: %w",
			err,
		)
	}

	committed = true

	return nil
}

var _ appresendverification.Repository = (*ResendVerificationRepository)(nil)
