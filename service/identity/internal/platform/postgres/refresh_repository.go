package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	apprefresh "github.com/DoMinhHHung/beexter/service/identity/internal/application/refresh"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const findIdentityForRefreshSQL = `
SELECT
    id::text,
    email,
    platform_role,
    status,
    email_verified_at,
    soft_delete_count,
    created_at,
    updated_at,
    deleted_at
FROM identity.identities
WHERE id = $1::uuid
`

var (
	ErrRefreshRepositoryNotInitialized = errors.New(
		"refresh repository is not initialized",
	)
	ErrRefreshRepositoryContextRequired = errors.New(
		"refresh repository context is required",
	)
)

type refreshDatabase interface {
	QueryRow(
		ctx context.Context,
		sql string,
		args ...any,
	) pgx.Row
}

type RefreshRepository struct {
	database refreshDatabase
}

func NewRefreshRepository(
	database refreshDatabase,
) (*RefreshRepository, error) {
	if database == nil {
		return nil, ErrRefreshRepositoryNotInitialized
	}

	return &RefreshRepository{database: database}, nil
}

func (r *RefreshRepository) FindByID(
	ctx context.Context,
	identityID identity.ID,
) (identity.Identity, error) {
	if r == nil || r.database == nil {
		return identity.Identity{}, ErrRefreshRepositoryNotInitialized
	}

	if ctx == nil {
		return identity.Identity{}, ErrRefreshRepositoryContextRequired
	}

	var (
		rawID           string
		email           string
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
		findIdentityForRefreshSQL,
		identityID.String(),
	).Scan(
		&rawID,
		&email,
		&rawPlatformRole,
		&rawStatus,
		&emailVerifiedAt,
		&softDeleteCount,
		&createdAt,
		&updatedAt,
		&deletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Identity{}, apprefresh.ErrIdentityNotFound
	}

	if err != nil {
		return identity.Identity{}, fmt.Errorf(
			"query identity for refresh: %w",
			err,
		)
	}

	parsedID, err := identity.ParseID(rawID)
	if err != nil {
		return identity.Identity{}, fmt.Errorf(
			"%w: parse refresh identity ID: %v",
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
		ID:              parsedID,
		Email:           email,
		PlatformRole:    platformRole,
		Status:          status,
		EmailVerified:   emailVerifiedAt != nil,
		SoftDeleteCount: uint8(softDeleteCount),
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
		DeletedAt:       deletedAt,
	}, nil
}

var _ apprefresh.Repository = (*RefreshRepository)(nil)
