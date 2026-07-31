package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appreactivation "github.com/DoMinhHHung/beexter/service/identity/internal/application/requestreactivation"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const findReactivationCandidateSQL = `
SELECT
    id::text,
    password_hash,
    status,
    deleted_at,
    soft_delete_count
FROM identity.identities
WHERE email = $1
`

const lockReactivationCandidateSQL = `
SELECT
    password_hash,
    status,
    deleted_at,
    soft_delete_count
FROM identity.identities
WHERE id = $1::uuid
FOR UPDATE
`

const revokeActiveVerificationTokensForReactivationSQL = `
UPDATE identity.email_verification_tokens
SET revoked_at = $2
WHERE identity_id = $1::uuid
  AND used_at IS NULL
  AND revoked_at IS NULL
`

const insertReactivationVerificationTokenSQL = `
INSERT INTO identity.email_verification_tokens (
    id,
    identity_id,
    expires_at,
    created_at
)
VALUES ($1::uuid, $2::uuid, $3, $4)
`

const insertReactivationOutboxSQL = `
INSERT INTO identity.outbox_events (
    id,
    aggregate_id,
    event_type,
    payload,
    available_at,
    created_at
)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $5)
`

var (
	ErrReactivationRepositoryNotInitialized = errors.New(
		"reactivation repository is not initialized",
	)
	ErrReactivationRepositoryContextRequired = errors.New(
		"reactivation repository context is required",
	)
)

type reactivationDatabase interface {
	transactionBeginner
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type ReactivationRepository struct {
	database reactivationDatabase
}

func NewReactivationRepository(
	database reactivationDatabase,
) (*ReactivationRepository, error) {
	if database == nil {
		return nil, ErrReactivationRepositoryNotInitialized
	}
	return &ReactivationRepository{database: database}, nil
}

func (r *ReactivationRepository) FindByEmail(
	ctx context.Context,
	email string,
) (appreactivation.Candidate, error) {
	if r == nil || r.database == nil {
		return appreactivation.Candidate{}, ErrReactivationRepositoryNotInitialized
	}
	if ctx == nil {
		return appreactivation.Candidate{}, ErrReactivationRepositoryContextRequired
	}

	var (
		rawID     string
		candidate appreactivation.Candidate
		rawStatus string
		softCount int16
	)
	err := r.database.QueryRow(
		ctx,
		findReactivationCandidateSQL,
		email,
	).Scan(
		&rawID,
		&candidate.PasswordHash,
		&rawStatus,
		&candidate.DeletedAt,
		&softCount,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return appreactivation.Candidate{}, appreactivation.ErrIdentityNotFound
	}
	if err != nil {
		return appreactivation.Candidate{}, fmt.Errorf(
			"query reactivation candidate: %w",
			err,
		)
	}

	identityID, err := identity.ParseID(rawID)
	if err != nil {
		return appreactivation.Candidate{}, fmt.Errorf(
			"%w: parse reactivation identity ID: %v",
			ErrInvalidPersistedIdentity,
			err,
		)
	}
	status := identity.Status(rawStatus)
	if (status != identity.StatusActive && status != identity.StatusInactive) ||
		softCount < 0 || softCount > 3 {
		return appreactivation.Candidate{}, fmt.Errorf(
			"%w: invalid reactivation identity state",
			ErrInvalidPersistedIdentity,
		)
	}
	candidate.IdentityID = identityID
	candidate.Status = status
	candidate.SoftDeleteCount = uint8(softCount)
	return candidate, nil
}

func (r *ReactivationRepository) Request(
	ctx context.Context,
	params appreactivation.CreateParams,
) (returnErr error) {
	if r == nil || r.database == nil {
		return ErrReactivationRepositoryNotInitialized
	}
	if ctx == nil {
		return ErrReactivationRepositoryContextRequired
	}

	tx, err := r.database.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite},
	)
	if err != nil {
		return fmt.Errorf("begin reactivation transaction: %w", err)
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
		wrapped := fmt.Errorf("rollback reactivation transaction: %w", rollbackErr)
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
		lockReactivationCandidateSQL,
		params.IdentityID.String(),
	).Scan(&passwordHash, &status, &deletedAt, &softCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return appreactivation.ErrIdentityNotFound
	}
	if err != nil {
		return fmt.Errorf("lock reactivation identity: %w", err)
	}
	if passwordHash != params.ExpectedPasswordHash {
		return appreactivation.ErrStateChanged
	}
	if status != string(identity.StatusInactive) || deletedAt == nil ||
		softCount < 1 || softCount > 3 {
		return appreactivation.ErrNotEligible
	}

	if _, err := tx.Exec(
		ctx,
		revokeActiveVerificationTokensForReactivationSQL,
		params.IdentityID.String(),
		params.CreatedAt,
	); err != nil {
		return fmt.Errorf("revoke active reactivation tokens: %w", err)
	}

	if _, err := tx.Exec(
		ctx,
		insertReactivationVerificationTokenSQL,
		params.VerificationTokenID,
		params.IdentityID.String(),
		params.ExpiresAt,
		params.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert reactivation verification token: %w", err)
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
		return fmt.Errorf("marshal reactivation outbox payload: %w", err)
	}

	if _, err := tx.Exec(
		ctx,
		insertReactivationOutboxSQL,
		params.OutboxEventID,
		params.IdentityID.String(),
		params.EventType,
		json.RawMessage(payload),
		params.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert reactivation outbox event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit reactivation transaction: %w", err)
	}
	committed = true
	return nil
}

var _ appreactivation.Repository = (*ReactivationRepository)(nil)
