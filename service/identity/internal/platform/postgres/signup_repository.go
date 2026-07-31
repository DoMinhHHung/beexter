package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appsignup "github.com/DoMinhHHung/beexter/service/identity/internal/application/signup"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	identityEmailUniqueConstraint = "identities_email_unique"
	uniqueViolationCode           = "23505"
	transactionRollbackTimeout    = 3 * time.Second
)

const insertIdentitySQL = `
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

const insertEmailVerificationTokenSQL = `
INSERT INTO identity.email_verification_tokens (
    id,
    identity_id,
    expires_at,
    created_at
)
VALUES ($1, $2, $3, $4)
`

const insertOutboxEventSQL = `
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
	ErrSignupRepositoryNotInitialized = errors.New(
		"signup repository is not initialized",
	)
	ErrSignupRepositoryContextRequired = errors.New(
		"signup repository context is required",
	)
)

type transactionBeginner interface {
	BeginTx(
		ctx context.Context,
		txOptions pgx.TxOptions,
	) (pgx.Tx, error)
}

type SignupRepository struct {
	database transactionBeginner
}

func NewSignupRepository(
	database transactionBeginner,
) (*SignupRepository, error) {
	if database == nil {
		return nil, ErrSignupRepositoryNotInitialized
	}

	return &SignupRepository{database: database}, nil
}

func (r *SignupRepository) Create(
	ctx context.Context,
	params appsignup.CreateParams,
) (returnErr error) {
	if r == nil || r.database == nil {
		return ErrSignupRepositoryNotInitialized
	}

	if ctx == nil {
		return ErrSignupRepositoryContextRequired
	}

	tx, err := r.database.BeginTx(
		ctx,
		pgx.TxOptions{
			IsoLevel:   pgx.ReadCommitted,
			AccessMode: pgx.ReadWrite,
		},
	)
	if err != nil {
		return fmt.Errorf("begin signup transaction: %w", err)
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
			"rollback signup transaction: %w",
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
		insertIdentitySQL,
		params.IdentityID.String(),
		params.Email,
		params.PasswordHash,
		string(params.Role),
		string(params.Status),
		params.CreatedAt,
	)
	if err != nil {
		if isIdentityEmailConflict(err) {
			return appsignup.ErrEmailAlreadyExists
		}
		return fmt.Errorf("insert identity: %w", err)
	}

	_, err = tx.Exec(
		ctx,
		insertEmailVerificationTokenSQL,
		params.VerificationTokenID,
		params.IdentityID.String(),
		params.VerificationTokenExpiresAt,
		params.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert email verification token: %w", err)
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
			"marshal email verification outbox payload: %w",
			err,
		)
	}

	_, err = tx.Exec(
		ctx,
		insertOutboxEventSQL,
		params.OutboxEventID,
		params.IdentityID.String(),
		params.OutboxEventType,
		json.RawMessage(payload),
		params.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert email verification outbox event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit signup transaction: %w", err)
	}

	committed = true
	return nil
}

func isIdentityEmailConflict(err error) bool {
	var postgresError *pgconn.PgError

	return errors.As(err, &postgresError) &&
		postgresError.Code == uniqueViolationCode &&
		postgresError.ConstraintName == identityEmailUniqueConstraint
}

var _ appsignup.Repository = (*SignupRepository)(nil)
