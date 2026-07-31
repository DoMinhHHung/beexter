package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	appcreateidentity "github.com/DoMinhHHung/beexter/service/identity/internal/application/createidentity"
	"github.com/jackc/pgx/v5"
)

const insertPrivilegedIdentitySQL = `
INSERT INTO identity.identities (
    id,
    email,
    password_hash,
    role,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $6)
`

const insertPrivilegedVerificationTokenSQL = `
INSERT INTO identity.email_verification_tokens (
    id,
    identity_id,
    expires_at,
    created_at
)
VALUES ($1, $2, $3, $4)
`

const insertPrivilegedOutboxEventSQL = `
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
	ErrPrivilegedIdentityRepositoryNotInitialized = errors.New(
		"privileged identity repository is not initialized",
	)
	ErrPrivilegedIdentityRepositoryContextRequired = errors.New(
		"privileged identity repository context is required",
	)
)

type PrivilegedIdentityRepository struct {
	database transactionBeginner
}

func NewPrivilegedIdentityRepository(
	database transactionBeginner,
) (*PrivilegedIdentityRepository, error) {
	if database == nil {
		return nil, ErrPrivilegedIdentityRepositoryNotInitialized
	}

	return &PrivilegedIdentityRepository{database: database}, nil
}

func (r *PrivilegedIdentityRepository) Create(
	ctx context.Context,
	params appcreateidentity.CreateParams,
) (returnErr error) {
	if r == nil || r.database == nil {
		return ErrPrivilegedIdentityRepositoryNotInitialized
	}

	if ctx == nil {
		return ErrPrivilegedIdentityRepositoryContextRequired
	}

	tx, err := r.database.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.ReadCommitted,
			AccessMode: pgx.ReadWrite,
		},
	)
	if err != nil {
		return fmt.Errorf("begin privileged identity transaction: %w", err)
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

		wrappedRollbackErr := fmt.Errorf(
			"rollback privileged identity transaction: %w",
			rollbackErr,
		)
		if returnErr == nil {
			returnErr = wrappedRollbackErr
			return
		}

		returnErr = errors.Join(returnErr, wrappedRollbackErr)
	}()

	_, err = tx.Exec(
		ctx,
		insertPrivilegedIdentitySQL,
		params.IdentityID.String(),
		params.Email,
		params.PasswordHash,
		string(params.Role),
		string(params.Status),
		params.CreatedAt,
	)
	if err != nil {
		if isIdentityEmailConflict(err) {
			return appcreateidentity.ErrEmailAlreadyExists
		}

		return fmt.Errorf("insert privileged identity: %w", err)
	}

	_, err = tx.Exec(
		ctx,
		insertPrivilegedVerificationTokenSQL,
		params.VerificationTokenID,
		params.IdentityID.String(),
		params.VerificationTokenExpiresAt,
		params.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf(
			"insert privileged identity verification token: %w",
			err,
		)
	}

	payload, err := json.Marshal(struct {
		IdentityID string `json:"identity_id"`
		TokenID    string `json:"token_id"`
		Locale     string `json:"locale"`
	}{
		IdentityID: params.IdentityID.String(),
		TokenID:    params.VerificationTokenID,
		Locale:     params.Locale,
	})
	if err != nil {
		return fmt.Errorf(
			"marshal privileged identity verification outbox payload: %w",
			err,
		)
	}

	_, err = tx.Exec(
		ctx,
		insertPrivilegedOutboxEventSQL,
		params.OutboxEventID,
		params.IdentityID.String(),
		params.OutboxEventType,
		json.RawMessage(payload),
		params.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf(
			"insert privileged identity verification outbox event: %w",
			err,
		)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit privileged identity transaction: %w", err)
	}

	committed = true
	return nil
}

var _ appcreateidentity.Repository = (*PrivilegedIdentityRepository)(nil)
