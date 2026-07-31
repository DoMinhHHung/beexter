package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	appresetpassword "github.com/DoMinhHHung/beexster/service/identity/internal/application/resetpassword"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const resolvePasswordResetTargetSQL = `
SELECT
    token.identity_id::text,
    token.expires_at,
    token.used_at,
    token.revoked_at,
    account.status,
    account.deleted_at
FROM identity.password_reset_tokens AS token
JOIN identity.identities AS account
    ON account.id = token.identity_id
WHERE token.id = $1::uuid
`

const selectPasswordResetForUpdateSQL = `
SELECT
    token.identity_id::text,
    token.expires_at,
    token.used_at,
    token.revoked_at,
    account.status,
    account.deleted_at
FROM identity.password_reset_tokens AS token
JOIN identity.identities AS account
    ON account.id = token.identity_id
WHERE token.id = $1::uuid
  AND token.identity_id = $2::uuid
FOR UPDATE OF token, account
`

const markPasswordResetTokenUsedSQL = `
UPDATE identity.password_reset_tokens
SET used_at = $3
WHERE id = $1::uuid
  AND identity_id = $2::uuid
  AND used_at IS NULL
  AND revoked_at IS NULL
`

const revokeOtherPasswordResetTokensSQL = `
UPDATE identity.password_reset_tokens
SET revoked_at = $3
WHERE identity_id = $1::uuid
  AND id <> $2::uuid
  AND used_at IS NULL
  AND revoked_at IS NULL
`

const updateResetPasswordHashSQL = `
UPDATE identity.identities
SET
    password_hash = $2,
    updated_at = $3
WHERE id = $1::uuid
  AND status = 'active'
  AND deleted_at IS NULL
`

const reopenPasswordResetOutboxForSessionRevocationSQL = `
UPDATE identity.outbox_events
SET
    payload = jsonb_set(
        jsonb_set(
            payload,
            '{phase}',
            to_jsonb('session_revocation'::text),
            true
        ),
        '{session_cutoff}',
        to_jsonb($4::text),
        true
    ),
    attempt_count = 0,
    available_at = $3,
    locked_at = NULL,
    lock_id = NULL,
    processed_at = NULL,
    last_error = NULL
WHERE aggregate_id = $1::uuid
  AND event_type = 'identity.password_reset_requested'
  AND payload ->> 'token_id' = $2
`

var (
	ErrResetPasswordRepositoryNotInitialized = errors.New(
		"reset-password repository is not initialized",
	)
	ErrResetPasswordRepositoryContextRequired = errors.New(
		"reset-password repository context is required",
	)
	ErrResetPasswordStateConflict = errors.New(
		"reset-password state changed unexpectedly",
	)
)

type resetPasswordDatabase interface {
	transactionBeginner

	QueryRow(
		ctx context.Context,
		sql string,
		args ...any,
	) pgx.Row
}

type ResetPasswordRepository struct {
	database resetPasswordDatabase
}

type passwordResetState struct {
	identityID string
	expiresAt  time.Time
	usedAt     *time.Time
	revokedAt  *time.Time
	status     string
	deletedAt  *time.Time
}

func NewResetPasswordRepository(
	database resetPasswordDatabase,
) (*ResetPasswordRepository, error) {
	if database == nil {
		return nil, ErrResetPasswordRepositoryNotInitialized
	}

	return &ResetPasswordRepository{database: database}, nil
}

func (r *ResetPasswordRepository) ResolveTarget(
	ctx context.Context,
	tokenID string,
	checkedAt time.Time,
) (identity.ID, error) {
	if r == nil || r.database == nil {
		return "", ErrResetPasswordRepositoryNotInitialized
	}
	if ctx == nil {
		return "", ErrResetPasswordRepositoryContextRequired
	}

	state, err := scanPasswordResetState(
		r.database.QueryRow(
			ctx,
			resolvePasswordResetTargetSQL,
			tokenID,
		),
	)
	if err != nil {
		return "", err
	}

	if err := validatePasswordResetState(state, checkedAt); err != nil {
		return "", err
	}

	identityID, err := identity.ParseID(state.identityID)
	if err != nil {
		return "", fmt.Errorf(
			"parse password-reset identity ID: %w",
			err,
		)
	}

	return identityID, nil
}

func (r *ResetPasswordRepository) Reset(
	ctx context.Context,
	params appresetpassword.ResetParams,
) (returnErr error) {
	if r == nil || r.database == nil {
		return ErrResetPasswordRepositoryNotInitialized
	}
	if ctx == nil {
		return ErrResetPasswordRepositoryContextRequired
	}

	tx, err := r.database.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.ReadCommitted,
			AccessMode: pgx.ReadWrite,
		},
	)
	if err != nil {
		return fmt.Errorf("begin reset-password transaction: %w", err)
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
			"rollback reset-password transaction: %w",
			rollbackErr,
		)
		if returnErr == nil {
			returnErr = wrappedRollbackError
			return
		}
		returnErr = errors.Join(returnErr, wrappedRollbackError)
	}()

	state, err := scanPasswordResetState(
		tx.QueryRow(
			ctx,
			selectPasswordResetForUpdateSQL,
			params.PasswordResetTokenID,
			params.IdentityID.String(),
		),
	)
	if err != nil {
		return err
	}

	if err := validatePasswordResetState(state, params.ResetAt); err != nil {
		return err
	}

	if state.identityID != params.IdentityID.String() {
		return ErrResetPasswordStateConflict
	}

	commandTag, err := tx.Exec(
		ctx,
		markPasswordResetTokenUsedSQL,
		params.PasswordResetTokenID,
		params.IdentityID.String(),
		params.ResetAt,
	)
	if err != nil {
		return fmt.Errorf("mark password-reset token used: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return ErrResetPasswordStateConflict
	}

	_, err = tx.Exec(
		ctx,
		revokeOtherPasswordResetTokensSQL,
		params.IdentityID.String(),
		params.PasswordResetTokenID,
		params.ResetAt,
	)
	if err != nil {
		return fmt.Errorf("revoke other password-reset tokens: %w", err)
	}

	commandTag, err = tx.Exec(
		ctx,
		updateResetPasswordHashSQL,
		params.IdentityID.String(),
		params.PasswordHash,
		params.ResetAt,
	)
	if err != nil {
		return fmt.Errorf("update reset password hash: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return ErrResetPasswordStateConflict
	}

	commandTag, err = tx.Exec(
		ctx,
		reopenPasswordResetOutboxForSessionRevocationSQL,
		params.IdentityID.String(),
		params.PasswordResetTokenID,
		params.SessionRevocationAvailableAt,
		params.ResetAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf(
			"reopen password-reset outbox for session revocation: %w",
			err,
		)
	}
	if commandTag.RowsAffected() != 1 {
		return ErrResetPasswordStateConflict
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit reset-password transaction: %w", err)
	}

	committed = true
	return nil
}

func scanPasswordResetState(row pgx.Row) (passwordResetState, error) {
	var state passwordResetState

	err := row.Scan(
		&state.identityID,
		&state.expiresAt,
		&state.usedAt,
		&state.revokedAt,
		&state.status,
		&state.deletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return passwordResetState{}, appresetpassword.ErrTokenNotFound
	}
	if err != nil {
		return passwordResetState{}, fmt.Errorf(
			"scan password-reset state: %w",
			err,
		)
	}

	return state, nil
}

func validatePasswordResetState(
	state passwordResetState,
	checkedAt time.Time,
) error {
	switch {
	case state.usedAt != nil:
		return appresetpassword.ErrTokenAlreadyUsed

	case state.revokedAt != nil:
		return appresetpassword.ErrTokenRevoked

	case !state.expiresAt.After(checkedAt):
		return appresetpassword.ErrTokenExpired

	case state.status != string(identity.StatusActive),
		state.deletedAt != nil:
		return appresetpassword.ErrAccountInactive

	default:
		return nil
	}
}

var _ appresetpassword.Repository = (*ResetPasswordRepository)(nil)
