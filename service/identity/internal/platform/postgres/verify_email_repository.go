package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	appverifyemail "github.com/DoMinhHHung/beexster/service/identity/internal/application/verifyemail"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const selectVerificationTokenForUpdateSQL = `
SELECT
    token.identity_id::text,
    token.expires_at,
    token.used_at,
    token.revoked_at,
    account.status,
    account.deleted_at
FROM identity.email_verification_tokens AS token
JOIN identity.identities AS account
    ON account.id = token.identity_id
WHERE token.id = $1::uuid
FOR UPDATE OF token, account
`

const markVerificationTokenUsedSQL = `
UPDATE identity.email_verification_tokens
SET used_at = $2
WHERE id = $1::uuid
  AND used_at IS NULL
  AND revoked_at IS NULL
`

const verifyIdentityEmailSQL = `
UPDATE identity.identities
SET
    email_verified_at = $2,
    status = CASE
        WHEN deleted_at IS NOT NULL THEN 'active'
        ELSE status
    END,
    deleted_at = CASE
        WHEN deleted_at IS NOT NULL THEN NULL
        ELSE deleted_at
    END,
    updated_at = $2
WHERE id = $1::uuid
`

var (
	ErrVerifyEmailRepositoryNotInitialized = errors.New(
		"verify-email repository is not initialized",
	)

	ErrVerifyEmailRepositoryContextRequired = errors.New(
		"verify-email repository context is required",
	)

	ErrVerificationStateConflict = errors.New(
		"email verification state changed unexpectedly",
	)
)

type VerifyEmailRepository struct {
	database transactionBeginner
}

func NewVerifyEmailRepository(
	database transactionBeginner,
) (*VerifyEmailRepository, error) {
	if database == nil {
		return nil, ErrVerifyEmailRepositoryNotInitialized
	}

	return &VerifyEmailRepository{
		database: database,
	}, nil
}

func (r *VerifyEmailRepository) Verify(
	ctx context.Context,
	tokenID string,
	verifiedAt time.Time,
) (
	result appverifyemail.Result,
	returnErr error,
) {
	if r == nil || r.database == nil {
		return appverifyemail.Result{},
			ErrVerifyEmailRepositoryNotInitialized
	}

	if ctx == nil {
		return appverifyemail.Result{},
			ErrVerifyEmailRepositoryContextRequired
	}

	tx, err := r.database.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.ReadCommitted,
			AccessMode: pgx.ReadWrite,
		},
	)
	if err != nil {
		return appverifyemail.Result{}, fmt.Errorf(
			"begin verify-email transaction: %w",
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
			errors.Is(rollbackErr, pgx.ErrTxClosed) {
			return
		}

		wrappedRollbackError := fmt.Errorf(
			"rollback verify-email transaction: %w",
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
		rawIdentityID string
		expiresAt     time.Time
		usedAt        *time.Time
		revokedAt     *time.Time
		status        string
		deletedAt     *time.Time
	)

	err = tx.QueryRow(
		ctx,
		selectVerificationTokenForUpdateSQL,
		tokenID,
	).Scan(
		&rawIdentityID,
		&expiresAt,
		&usedAt,
		&revokedAt,
		&status,
		&deletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return appverifyemail.Result{},
			appverifyemail.ErrTokenNotFound
	}

	if err != nil {
		return appverifyemail.Result{}, fmt.Errorf(
			"select verification token for update: %w",
			err,
		)
	}

	identityID, err := identity.ParseID(rawIdentityID)
	if err != nil {
		return appverifyemail.Result{}, fmt.Errorf(
			"parse verification identity ID: %w",
			err,
		)
	}

	if usedAt != nil {
		return appverifyemail.Result{},
			appverifyemail.ErrTokenAlreadyUsed
	}

	if revokedAt != nil {
		return appverifyemail.Result{},
			appverifyemail.ErrTokenRevoked
	}

	if !expiresAt.After(verifiedAt) {
		return appverifyemail.Result{},
			appverifyemail.ErrTokenExpired
	}

	reactivated := false

	switch {
	case status == string(identity.StatusActive) &&
		deletedAt == nil:
		// Standard verification after signup.

	case status == string(identity.StatusInactive) &&
		deletedAt != nil:
		// Re-verification after soft delete.
		reactivated = true

	default:
		return appverifyemail.Result{},
			appverifyemail.ErrAccountInactive
	}

	commandTag, err := tx.Exec(
		ctx,
		markVerificationTokenUsedSQL,
		tokenID,
		verifiedAt,
	)
	if err != nil {
		return appverifyemail.Result{}, fmt.Errorf(
			"mark verification token used: %w",
			err,
		)
	}

	if commandTag.RowsAffected() != 1 {
		return appverifyemail.Result{},
			ErrVerificationStateConflict
	}

	commandTag, err = tx.Exec(
		ctx,
		verifyIdentityEmailSQL,
		identityID.String(),
		verifiedAt,
	)
	if err != nil {
		return appverifyemail.Result{}, fmt.Errorf(
			"verify identity email: %w",
			err,
		)
	}

	if commandTag.RowsAffected() != 1 {
		return appverifyemail.Result{},
			ErrVerificationStateConflict
	}

	if err := tx.Commit(ctx); err != nil {
		return appverifyemail.Result{}, fmt.Errorf(
			"commit verify-email transaction: %w",
			err,
		)
	}

	committed = true

	return appverifyemail.Result{
		IdentityID:  identityID,
		Reactivated: reactivated,
	}, nil
}

var _ appverifyemail.Repository = (*VerifyEmailRepository)(nil)
