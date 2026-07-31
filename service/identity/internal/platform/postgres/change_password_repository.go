package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	appchangepassword "github.com/DoMinhHHung/beexster/service/identity/internal/application/changepassword"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const loadChangePasswordCredentialSQL = `
SELECT
    password_hash,
    status,
    deleted_at
FROM identity.identities
WHERE id = $1::uuid
`

const selectChangePasswordCredentialForUpdateSQL = `
SELECT
    password_hash,
    status,
    deleted_at
FROM identity.identities
WHERE id = $1::uuid
FOR UPDATE
`

const revokeActivePasswordResetTokensAfterChangeSQL = `
UPDATE identity.password_reset_tokens
SET revoked_at = $2
WHERE identity_id = $1::uuid
  AND used_at IS NULL
  AND revoked_at IS NULL
`

const updateChangedPasswordHashSQL = `
UPDATE identity.identities
SET
    password_hash = $2,
    updated_at = $3
WHERE id = $1::uuid
  AND status = 'active'
  AND deleted_at IS NULL
`

var (
	ErrChangePasswordRepositoryNotInitialized = errors.New(
		"change-password repository is not initialized",
	)
	ErrChangePasswordRepositoryContextRequired = errors.New(
		"change-password repository context is required",
	)
	ErrChangePasswordStateConflict = errors.New(
		"change-password state changed unexpectedly",
	)
)

type changePasswordDatabase interface {
	transactionBeginner

	QueryRow(
		ctx context.Context,
		sql string,
		args ...any,
	) pgx.Row
}

type ChangePasswordRepository struct {
	database changePasswordDatabase
}

type changePasswordState struct {
	passwordHash string
	status       string
	deletedAt    *time.Time
}

func NewChangePasswordRepository(
	database changePasswordDatabase,
) (*ChangePasswordRepository, error) {
	if database == nil {
		return nil, ErrChangePasswordRepositoryNotInitialized
	}

	return &ChangePasswordRepository{database: database}, nil
}

func (r *ChangePasswordRepository) LoadCredential(
	ctx context.Context,
	identityID identity.ID,
) (appchangepassword.Credential, error) {
	if r == nil || r.database == nil {
		return appchangepassword.Credential{},
			ErrChangePasswordRepositoryNotInitialized
	}
	if ctx == nil {
		return appchangepassword.Credential{},
			ErrChangePasswordRepositoryContextRequired
	}

	state, err := scanChangePasswordState(
		r.database.QueryRow(
			ctx,
			loadChangePasswordCredentialSQL,
			identityID.String(),
		),
	)
	if err != nil {
		return appchangepassword.Credential{}, err
	}

	return appchangepassword.Credential{
		PasswordHash: state.passwordHash,
		Status:       identity.Status(state.status),
		DeletedAt:    state.deletedAt,
	}, nil
}

func (r *ChangePasswordRepository) ChangePassword(
	ctx context.Context,
	params appchangepassword.ChangeParams,
) (returnErr error) {
	if r == nil || r.database == nil {
		return ErrChangePasswordRepositoryNotInitialized
	}
	if ctx == nil {
		return ErrChangePasswordRepositoryContextRequired
	}

	tx, err := r.database.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.ReadCommitted,
			AccessMode: pgx.ReadWrite,
		},
	)
	if err != nil {
		return fmt.Errorf("begin change-password transaction: %w", err)
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
			"rollback change-password transaction: %w",
			rollbackErr,
		)
		if returnErr == nil {
			returnErr = wrappedRollbackError
			return
		}
		returnErr = errors.Join(returnErr, wrappedRollbackError)
	}()

	state, err := scanChangePasswordState(
		tx.QueryRow(
			ctx,
			selectChangePasswordCredentialForUpdateSQL,
			params.IdentityID.String(),
		),
	)
	if err != nil {
		return err
	}
	if err := validateChangePasswordState(state); err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(
		[]byte(state.passwordHash),
		[]byte(params.ExpectedPasswordHash),
	) != 1 {
		return appchangepassword.ErrCredentialChanged
	}

	_, err = tx.Exec(
		ctx,
		revokeActivePasswordResetTokensAfterChangeSQL,
		params.IdentityID.String(),
		params.ChangedAt,
	)
	if err != nil {
		return fmt.Errorf(
			"revoke password-reset tokens after password change: %w",
			err,
		)
	}

	commandTag, err := tx.Exec(
		ctx,
		updateChangedPasswordHashSQL,
		params.IdentityID.String(),
		params.NewPasswordHash,
		params.ChangedAt,
	)
	if err != nil {
		return fmt.Errorf("update changed password hash: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return ErrChangePasswordStateConflict
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit change-password transaction: %w", err)
	}

	committed = true
	return nil
}

func scanChangePasswordState(row pgx.Row) (changePasswordState, error) {
	var state changePasswordState

	err := row.Scan(
		&state.passwordHash,
		&state.status,
		&state.deletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return changePasswordState{}, appchangepassword.ErrIdentityNotFound
	}
	if err != nil {
		return changePasswordState{}, fmt.Errorf(
			"scan change-password state: %w",
			err,
		)
	}

	return state, nil
}

func validateChangePasswordState(state changePasswordState) error {
	if state.status != string(identity.StatusActive) || state.deletedAt != nil {
		return appchangepassword.ErrAccountInactive
	}
	if state.passwordHash == "" {
		return ErrChangePasswordStateConflict
	}
	return nil
}

var _ appchangepassword.Repository = (*ChangePasswordRepository)(nil)
