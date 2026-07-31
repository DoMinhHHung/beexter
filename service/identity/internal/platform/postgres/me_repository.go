package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	getmeapp "github.com/DoMinhHHung/beexster/service/identity/internal/application/getme"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const findMeIdentitySQL = `
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
	ErrMeRepositoryNotInitialized  = errors.New("me repository is not initialized")
	ErrMeRepositoryContextRequired = errors.New(
		"me repository context is required",
	)
)

type meDatabase interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type MeRepository struct {
	database meDatabase
}

func NewMeRepository(database meDatabase) (*MeRepository, error) {
	if database == nil {
		return nil, ErrMeRepositoryNotInitialized
	}

	return &MeRepository{database: database}, nil
}

func (r *MeRepository) FindByID(
	ctx context.Context,
	userID identity.ID,
) (identity.Identity, error) {
	if r == nil || r.database == nil {
		return identity.Identity{}, ErrMeRepositoryNotInitialized
	}
	if ctx == nil {
		return identity.Identity{}, ErrMeRepositoryContextRequired
	}
	if userID.IsZero() {
		return identity.Identity{}, errors.New("me repository user ID is required")
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
		findMeIdentitySQL,
		userID.String(),
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
		return identity.Identity{}, getmeapp.ErrIdentityNotFound
	}
	if err != nil {
		return identity.Identity{}, fmt.Errorf("query current identity: %w", err)
	}

	parsedID, err := identity.ParseID(rawID)
	if err != nil {
		return identity.Identity{}, fmt.Errorf(
			"%w: parse current identity ID: %v",
			ErrInvalidPersistedIdentity,
			err,
		)
	}

	normalizedEmail, err := identity.NormalizeAndValidateEmail(email)
	if err != nil || normalizedEmail != email {
		return identity.Identity{}, fmt.Errorf(
			"%w: invalid persisted email",
			ErrInvalidPersistedIdentity,
		)
	}

	platformRole, err := platformRoleFromNullString(rawPlatformRole)
	if err != nil {
		return identity.Identity{}, err
	}

	status := identity.Status(rawStatus)
	if status != identity.StatusActive && status != identity.StatusInactive {
		return identity.Identity{}, fmt.Errorf(
			"%w: unknown status %q",
			ErrInvalidPersistedIdentity,
			rawStatus,
		)
	}

	if softDeleteCount < 0 || softDeleteCount > 3 ||
		createdAt.IsZero() || updatedAt.Before(createdAt) {
		return identity.Identity{}, fmt.Errorf(
			"%w: invalid persisted identity state",
			ErrInvalidPersistedIdentity,
		)
	}

	return identity.Identity{
		ID:              parsedID,
		Email:           email,
		PlatformRole:    platformRole,
		Status:          status,
		EmailVerified:   emailVerifiedAt != nil,
		SoftDeleteCount: uint8(softDeleteCount),
		CreatedAt:       createdAt.UTC(),
		UpdatedAt:       updatedAt.UTC(),
		DeletedAt:       deletedAt,
	}, nil
}

var _ getmeapp.Repository = (*MeRepository)(nil)
