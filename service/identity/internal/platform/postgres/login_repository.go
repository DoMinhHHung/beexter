package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	applogin "github.com/DoMinhHHung/beexster/service/identity/internal/application/login"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const findIdentityForLoginSQL = `
SELECT
    id::text,
    email,
    password_hash,
    platform_role,
    status,
    email_verified_at,
    soft_delete_count,
    created_at,
    updated_at,
    deleted_at
FROM identity.identities
WHERE email = $1
`

const insertLoginAttemptSQL = `
INSERT INTO identity.login_attempts (
    id,
    identity_id,
    email,
    success,
    failure_code,
    ip_address,
    user_agent,
    request_id,
    attempted_at
)
VALUES (
    $1::uuid,
    $2::uuid,
    $3,
    $4,
    $5,
    $6::inet,
    $7,
    $8,
    $9
)
`

var (
	ErrLoginRepositoryNotInitialized = errors.New(
		"login repository is not initialized",
	)

	ErrLoginRepositoryContextRequired = errors.New(
		"login repository context is required",
	)

	ErrInvalidPersistedIdentity = errors.New(
		"persisted identity is invalid",
	)
)

type loginDatabase interface {
	QueryRow(
		ctx context.Context,
		sql string,
		args ...any,
	) pgx.Row

	Exec(
		ctx context.Context,
		sql string,
		args ...any,
	) (pgconn.CommandTag, error)
}

type LoginRepository struct {
	database loginDatabase
}

func NewLoginRepository(
	database loginDatabase,
) (*LoginRepository, error) {
	if database == nil {
		return nil, ErrLoginRepositoryNotInitialized
	}

	return &LoginRepository{
		database: database,
	}, nil
}

func (r *LoginRepository) FindByEmail(
	ctx context.Context,
	email string,
) (identity.Identity, error) {
	if r == nil || r.database == nil {
		return identity.Identity{}, ErrLoginRepositoryNotInitialized
	}

	if ctx == nil {
		return identity.Identity{}, ErrLoginRepositoryContextRequired
	}

	var (
		rawID           string
		persistedEmail  string
		passwordHash    string
		rawPlatformRole sql.NullString
		rawStatus       string
		emailVerifiedAt *time.Time
		softDeleteCount int16
		createdAt       time.Time
		updatedAt       time.Time
		deletedAt       *time.Time
	)

	err := r.database.QueryRow(
		ctx,
		findIdentityForLoginSQL,
		email,
	).Scan(
		&rawID,
		&persistedEmail,
		&passwordHash,
		&rawPlatformRole,
		&rawStatus,
		&emailVerifiedAt,
		&softDeleteCount,
		&createdAt,
		&updatedAt,
		&deletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Identity{}, applogin.ErrIdentityNotFound
	}

	if err != nil {
		return identity.Identity{}, fmt.Errorf(
			"query identity for login: %w",
			err,
		)
	}

	identityID, err := identity.ParseID(rawID)
	if err != nil {
		return identity.Identity{}, fmt.Errorf(
			"%w: parse identity ID: %v",
			ErrInvalidPersistedIdentity,
			err,
		)
	}

	platformRole, err := platformRoleFromNullString(rawPlatformRole)
	if err != nil {
		return identity.Identity{}, err
	}

	status := identity.Status(rawStatus)
	if status != identity.StatusActive &&
		status != identity.StatusInactive {
		return identity.Identity{}, fmt.Errorf(
			"%w: unknown status %q",
			ErrInvalidPersistedIdentity,
			rawStatus,
		)
	}

	if softDeleteCount < 0 || softDeleteCount > 3 {
		return identity.Identity{}, fmt.Errorf(
			"%w: invalid soft-delete count %d",
			ErrInvalidPersistedIdentity,
			softDeleteCount,
		)
	}

	return identity.Identity{
		ID:              identityID,
		Email:           persistedEmail,
		PasswordHash:    passwordHash,
		PlatformRole:    platformRole,
		Status:          status,
		EmailVerified:   emailVerifiedAt != nil,
		SoftDeleteCount: uint8(softDeleteCount),
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
		DeletedAt:       deletedAt,
	}, nil
}

func (r *LoginRepository) RecordAttempt(
	ctx context.Context,
	attempt applogin.Attempt,
) error {
	if r == nil || r.database == nil {
		return ErrLoginRepositoryNotInitialized
	}

	if ctx == nil {
		return ErrLoginRepositoryContextRequired
	}

	var rawIdentityID any
	if attempt.IdentityID != nil {
		rawIdentityID = attempt.IdentityID.String()
	}

	var failureCode any
	if !attempt.Success {
		failureCode = attempt.FailureCode
	}

	commandTag, err := r.database.Exec(
		ctx,
		insertLoginAttemptSQL,
		attempt.ID,
		rawIdentityID,
		attempt.Email,
		attempt.Success,
		failureCode,
		attempt.IPAddress.Unmap().String(),
		attempt.UserAgent,
		attempt.RequestID,
		attempt.AttemptedAt,
	)
	if err != nil {
		return fmt.Errorf("insert login attempt: %w", err)
	}

	if commandTag.RowsAffected() != 1 {
		return errors.New("insert login attempt affected unexpected row count")
	}

	return nil
}

var _ applogin.Repository = (*LoginRepository)(nil)
