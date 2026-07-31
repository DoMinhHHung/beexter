package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	appdeleteaccount "github.com/DoMinhHHung/beexter/service/identity/internal/application/deleteaccount"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const loadDeleteAccountCredentialSQL = `
SELECT
    password_hash,
    status,
    deleted_at,
    soft_delete_count
FROM identity.identities
WHERE id = $1::uuid
`

const lockDeleteAccountIdentitySQL = `
SELECT
    password_hash,
    status,
    deleted_at,
    soft_delete_count
FROM identity.identities
WHERE id = $1::uuid
FOR UPDATE
`

const revokeVerificationTokensForDeleteSQL = `
UPDATE identity.email_verification_tokens
SET revoked_at = GREATEST($2, created_at)
WHERE identity_id = $1::uuid
  AND used_at IS NULL
  AND revoked_at IS NULL
`

const revokePasswordResetTokensForDeleteSQL = `
UPDATE identity.password_reset_tokens
SET revoked_at = GREATEST($2, created_at)
WHERE identity_id = $1::uuid
  AND used_at IS NULL
  AND revoked_at IS NULL
`

const softDeleteIdentitySQL = `
UPDATE identity.identities
SET
    status = 'inactive',
    email_verified_at = NULL,
    soft_delete_count = soft_delete_count + 1,
    updated_at = GREATEST(updated_at, $2),
    deleted_at = GREATEST(updated_at, $2)
WHERE id = $1::uuid
`

const hardDeleteIdentitySQL = `
DELETE FROM identity.identities
WHERE id = $1::uuid
`

var (
	ErrDeleteAccountRepositoryNotInitialized = errors.New(
		"delete-account repository is not initialized",
	)
	ErrDeleteAccountRepositoryContextRequired = errors.New(
		"delete-account repository context is required",
	)
)

type deleteAccountDatabase interface {
	transactionBeginner
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type DeleteAccountRepository struct {
	database deleteAccountDatabase
}

func NewDeleteAccountRepository(
	database deleteAccountDatabase,
) (*DeleteAccountRepository, error) {
	if database == nil {
		return nil, ErrDeleteAccountRepositoryNotInitialized
	}
	return &DeleteAccountRepository{database: database}, nil
}

func (r *DeleteAccountRepository) LoadCredential(
	ctx context.Context,
	identityID identity.ID,
) (appdeleteaccount.Credential, error) {
	if r == nil || r.database == nil {
		return appdeleteaccount.Credential{},
			ErrDeleteAccountRepositoryNotInitialized
	}
	if ctx == nil {
		return appdeleteaccount.Credential{},
			ErrDeleteAccountRepositoryContextRequired
	}

	var (
		credential appdeleteaccount.Credential
		rawStatus  string
		softCount  int16
	)
	err := r.database.QueryRow(
		ctx,
		loadDeleteAccountCredentialSQL,
		identityID.String(),
	).Scan(
		&credential.PasswordHash,
		&rawStatus,
		&credential.DeletedAt,
		&softCount,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return appdeleteaccount.Credential{}, appdeleteaccount.ErrIdentityNotFound
	}
	if err != nil {
		return appdeleteaccount.Credential{}, fmt.Errorf(
			"load delete-account credential: %w",
			err,
		)
	}

	status := identity.Status(rawStatus)
	if (status != identity.StatusActive && status != identity.StatusInactive) ||
		softCount < 0 || softCount > 3 {
		return appdeleteaccount.Credential{}, fmt.Errorf(
			"%w: invalid delete-account identity state",
			ErrInvalidPersistedIdentity,
		)
	}
	credential.Status = status
	credential.SoftDeleteCount = uint8(softCount)
	return credential, nil
}

func (r *DeleteAccountRepository) DeleteAccount(
	ctx context.Context,
	params appdeleteaccount.DeleteParams,
) (result appdeleteaccount.DeleteResult, returnErr error) {
	if r == nil || r.database == nil {
		return result, ErrDeleteAccountRepositoryNotInitialized
	}
	if ctx == nil {
		return result, ErrDeleteAccountRepositoryContextRequired
	}

	tx, err := r.database.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite},
	)
	if err != nil {
		return result, fmt.Errorf("begin delete-account transaction: %w", err)
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
		wrapped := fmt.Errorf("rollback delete-account transaction: %w", rollbackErr)
		if returnErr == nil {
			returnErr = wrapped
		} else {
			returnErr = errors.Join(returnErr, wrapped)
		}
	}()

	var (
		passwordHash string
		status       string
		deletedAt    *time.Time
		softCount    int16
	)
	err = tx.QueryRow(
		ctx,
		lockDeleteAccountIdentitySQL,
		params.IdentityID.String(),
	).Scan(&passwordHash, &status, &deletedAt, &softCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, appdeleteaccount.ErrIdentityNotFound
	}
	if err != nil {
		return result, fmt.Errorf("lock identity for account deletion: %w", err)
	}
	if status != string(identity.StatusActive) || deletedAt != nil {
		return result, appdeleteaccount.ErrAccountInactive
	}
	if passwordHash != params.ExpectedPasswordHash {
		return result, appdeleteaccount.ErrCredentialChanged
	}
	if softCount < 0 || softCount > 3 {
		return result, fmt.Errorf(
			"%w: invalid soft-delete count %d",
			ErrInvalidPersistedIdentity,
			softCount,
		)
	}

	for _, statement := range []string{
		revokeVerificationTokensForDeleteSQL,
		revokePasswordResetTokensForDeleteSQL,
	} {
		if _, err := tx.Exec(
			ctx,
			statement,
			params.IdentityID.String(),
			params.DeletedAt,
		); err != nil {
			return result, fmt.Errorf("revoke account lifecycle token: %w", err)
		}
	}

	if softCount >= 3 {
		commandTag, err := tx.Exec(
			ctx,
			hardDeleteIdentitySQL,
			params.IdentityID.String(),
		)
		if err != nil {
			return result, fmt.Errorf("hard delete identity: %w", err)
		}
		if commandTag.RowsAffected() != 1 {
			return result, appdeleteaccount.ErrIdentityNotFound
		}
		result = appdeleteaccount.DeleteResult{
			HardDeleted:     true,
			SoftDeleteCount: 3,
		}
	} else {
		commandTag, err := tx.Exec(
			ctx,
			softDeleteIdentitySQL,
			params.IdentityID.String(),
			params.DeletedAt,
		)
		if err != nil {
			return result, fmt.Errorf("soft delete identity: %w", err)
		}
		if commandTag.RowsAffected() != 1 {
			return result, appdeleteaccount.ErrIdentityNotFound
		}
		result = appdeleteaccount.DeleteResult{
			HardDeleted:     false,
			SoftDeleteCount: uint8(softCount + 1),
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("commit delete-account transaction: %w", err)
	}
	committed = true
	return result, nil
}

var _ appdeleteaccount.Repository = (*DeleteAccountRepository)(nil)
