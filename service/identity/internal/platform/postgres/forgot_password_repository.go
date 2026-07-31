package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appforgotpassword "github.com/DoMinhHHung/beexster/service/identity/internal/application/forgotpassword"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const selectIdentityForPasswordResetSQL = `
SELECT
    id::text,
    status,
    deleted_at
FROM identity.identities
WHERE email = $1
FOR UPDATE
`

const revokeActivePasswordResetTokensSQL = `
UPDATE identity.password_reset_tokens
SET revoked_at = $2
WHERE identity_id = $1::uuid
  AND used_at IS NULL
  AND revoked_at IS NULL
`

const insertPasswordResetTokenSQL = `
INSERT INTO identity.password_reset_tokens (
    id,
    identity_id,
    expires_at,
    created_at
)
VALUES ($1, $2, $3, $4)
`

const insertPasswordResetOutboxSQL = `
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
	ErrForgotPasswordRepositoryNotInitialized = errors.New(
		"forgot-password repository is not initialized",
	)
	ErrForgotPasswordRepositoryContextRequired = errors.New(
		"forgot-password repository context is required",
	)
)

type ForgotPasswordRepository struct {
	database transactionBeginner
}

func NewForgotPasswordRepository(
	database transactionBeginner,
) (*ForgotPasswordRepository, error) {
	if database == nil {
		return nil, ErrForgotPasswordRepositoryNotInitialized
	}

	return &ForgotPasswordRepository{database: database}, nil
}

func (r *ForgotPasswordRepository) RequestReset(
	ctx context.Context,
	params appforgotpassword.CreateParams,
) (returnErr error) {
	if r == nil || r.database == nil {
		return ErrForgotPasswordRepositoryNotInitialized
	}
	if ctx == nil {
		return ErrForgotPasswordRepositoryContextRequired
	}

	tx, err := r.database.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.ReadCommitted,
			AccessMode: pgx.ReadWrite,
		},
	)
	if err != nil {
		return fmt.Errorf("begin forgot-password transaction: %w", err)
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

		wrappedRollbackError := fmt.Errorf(
			"rollback forgot-password transaction: %w",
			rollbackErr,
		)
		if returnErr == nil {
			returnErr = wrappedRollbackError
			return
		}
		returnErr = errors.Join(returnErr, wrappedRollbackError)
	}()

	var (
		rawIdentityID string
		status        string
		deletedAt     *time.Time
	)

	err = tx.QueryRow(
		ctx,
		selectIdentityForPasswordResetSQL,
		params.Email,
	).Scan(
		&rawIdentityID,
		&status,
		&deletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		// Generic success prevents account enumeration.
		return nil
	}
	if err != nil {
		return fmt.Errorf("select identity for password reset: %w", err)
	}

	identityID, err := identity.ParseID(rawIdentityID)
	if err != nil {
		return fmt.Errorf("parse password-reset identity ID: %w", err)
	}

	if status != string(identity.StatusActive) || deletedAt != nil {
		// Inactive and soft-deleted accounts are intentionally indistinguishable
		// from nonexistent accounts at the HTTP boundary.
		return nil
	}

	_, err = tx.Exec(
		ctx,
		revokeActivePasswordResetTokensSQL,
		identityID.String(),
		params.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("revoke active password-reset tokens: %w", err)
	}

	_, err = tx.Exec(
		ctx,
		insertPasswordResetTokenSQL,
		params.PasswordResetTokenID,
		identityID.String(),
		params.PasswordResetTokenExpiresAt,
		params.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert password-reset token: %w", err)
	}

	payload, err := json.Marshal(struct {
		IdentityID string `json:"identity_id"`
		TokenID    string `json:"token_id"`
		Locale     string `json:"locale"`
	}{
		IdentityID: identityID.String(),
		TokenID:    params.PasswordResetTokenID,
		Locale:     params.Locale,
	})
	if err != nil {
		return fmt.Errorf("marshal password-reset outbox payload: %w", err)
	}

	_, err = tx.Exec(
		ctx,
		insertPasswordResetOutboxSQL,
		params.OutboxEventID,
		identityID.String(),
		params.OutboxEventType,
		json.RawMessage(payload),
		params.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert password-reset outbox event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit forgot-password transaction: %w", err)
	}

	committed = true
	return nil
}

var _ appforgotpassword.Repository = (*ForgotPasswordRepository)(nil)
