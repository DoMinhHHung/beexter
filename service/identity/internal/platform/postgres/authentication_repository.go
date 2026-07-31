package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	authenticateapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/authenticate"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

const findIdentityForAuthenticationSQL = `
SELECT
    id::text,
    email,
    role,
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
	ErrAuthenticationRepositoryNotInitialized = errors.New(
		"authentication repository is not initialized",
	)
	ErrAuthenticationRepositoryContextRequired = errors.New(
		"authentication repository context is required",
	)
)

type authenticationDatabase interface {
	QueryRow(
		ctx context.Context,
		sql string,
		args ...any,
	) pgx.Row
}

type AuthenticationRepository struct {
	database authenticationDatabase
}

func NewAuthenticationRepository(
	database authenticationDatabase,
) (*AuthenticationRepository, error) {
	if database == nil {
		return nil, ErrAuthenticationRepositoryNotInitialized
	}

	return &AuthenticationRepository{database: database}, nil
}

func (r *AuthenticationRepository) FindByID(
	ctx context.Context,
	identityID identity.ID,
) (identity.Identity, error) {
	if r == nil || r.database == nil {
		return identity.Identity{}, ErrAuthenticationRepositoryNotInitialized
	}

	if ctx == nil {
		return identity.Identity{}, ErrAuthenticationRepositoryContextRequired
	}

	var (
		rawID           string
		email           string
		rawRole         string
		rawStatus       string
		emailVerifiedAt *time.Time
		softDeleteCount int16
		createdAt       time.Time
		updatedAt       time.Time
		deletedAt       *time.Time
	)

	err := r.database.QueryRow(
		ctx,
		findIdentityForAuthenticationSQL,
		identityID.String(),
	).Scan(
		&rawID,
		&email,
		&rawRole,
		&rawStatus,
		&emailVerifiedAt,
		&softDeleteCount,
		&createdAt,
		&updatedAt,
		&deletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Identity{}, authenticateapp.ErrIdentityNotFound
	}

	if err != nil {
		return identity.Identity{}, fmt.Errorf(
			"query identity for authentication: %w",
			err,
		)
	}

	parsedID, err := identity.ParseID(rawID)
	if err != nil {
		return identity.Identity{}, fmt.Errorf(
			"%w: parse authentication identity ID: %v",
			ErrInvalidPersistedIdentity,
			err,
		)
	}

	role := identity.Role(rawRole)
	if !role.IsValid() {
		return identity.Identity{}, fmt.Errorf(
			"%w: unknown role %q",
			ErrInvalidPersistedIdentity,
			rawRole,
		)
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
		Role:            role,
		Status:          status,
		EmailVerified:   emailVerifiedAt != nil,
		SoftDeleteCount: uint8(softDeleteCount),
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
		DeletedAt:       deletedAt,
	}, nil
}

var _ authenticateapp.Repository = (*AuthenticationRepository)(nil)
