package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appcreateidentity "github.com/DoMinhHHung/beexter/service/identity/internal/application/createidentity"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const lockPrivilegedActorSQL = `
SELECT
    platform_role,
    status,
    email_verified_at,
    deleted_at
FROM identity.identities
WHERE id = $1::uuid
FOR UPDATE
`

const insertPrivilegedIdentitySQL = `
INSERT INTO identity.identities (
    id,
    email,
    password_hash,
    platform_role,
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

type privilegedActorQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
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

	if params.ActorID.IsZero() ||
		params.PlatformRole != identity.PlatformRoleViceAdmin {
		return appcreateidentity.ErrActorForbidden
	}

	if err := authorizePrivilegedActor(ctx, tx, params.ActorID); err != nil {
		return err
	}

	_, err = tx.Exec(
		ctx,
		insertPrivilegedIdentitySQL,
		params.IdentityID.String(),
		params.Email,
		params.PasswordHash,
		string(params.PlatformRole),
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

func authorizePrivilegedActor(
	ctx context.Context,
	database privilegedActorQuerier,
	actorID identity.ID,
) error {
	var (
		rawPlatformRole sql.NullString
		rawStatus       string
		emailVerifiedAt *time.Time
		deletedAt       *time.Time
	)

	err := database.QueryRow(
		ctx,
		lockPrivilegedActorSQL,
		actorID.String(),
	).Scan(
		&rawPlatformRole,
		&rawStatus,
		&emailVerifiedAt,
		&deletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return appcreateidentity.ErrActorForbidden
	}
	if err != nil {
		return fmt.Errorf("lock privileged identity actor: %w", err)
	}

	platformRole, roleErr := platformRoleFromNullString(rawPlatformRole)
	if roleErr != nil ||
		platformRole != identity.PlatformRoleAdmin ||
		identity.Status(rawStatus) != identity.StatusActive ||
		emailVerifiedAt == nil ||
		deletedAt != nil {
		return appcreateidentity.ErrActorForbidden
	}

	return nil
}

var _ appcreateidentity.Repository = (*PrivilegedIdentityRepository)(nil)
