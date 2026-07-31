package createidentity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	domainlocale "github.com/DoMinhHHung/beexter/service/identity/internal/domain/locale"
)

const (
	emailVerificationTokenTTL  = time.Hour
	emailVerificationEventType = "identity.email_verification_requested"
)

var (
	ErrDependencyMissing  = errors.New("create-identity dependency is missing")
	ErrEmailAlreadyExists = errors.New("email already exists")
)

type Input struct {
	ActorID   identity.ID
	ActorRole identity.Role
	Email     string
	Password  string
	Role      string
	Locale    string
}

type Output struct {
	ID    identity.ID
	Email string
	Role  identity.Role
}

type CreateParams struct {
	IdentityID                 identity.ID
	VerificationTokenID        string
	OutboxEventID              string
	Email                      string
	PasswordHash               string
	Role                       identity.Role
	Status                     identity.Status
	Locale                     string
	CreatedAt                  time.Time
	VerificationTokenExpiresAt time.Time
	OutboxEventType            string
}

type Repository interface {
	Create(ctx context.Context, params CreateParams) error
}

type PasswordHasher interface {
	Hash(password string) (string, error)
}

type IdentityIDGenerator interface {
	Generate() (identity.ID, error)
}

type UUIDGenerator interface {
	GenerateString() (string, error)
}

type UseCase struct {
	repository  Repository
	hasher      PasswordHasher
	identityIDs IdentityIDGenerator
	uuidIDs     UUIDGenerator
	now         func() time.Time
}

func New(
	repository Repository,
	hasher PasswordHasher,
	identityIDs IdentityIDGenerator,
	uuidIDs UUIDGenerator,
	now func() time.Time,
) (*UseCase, error) {
	if repository == nil ||
		hasher == nil ||
		identityIDs == nil ||
		uuidIDs == nil ||
		now == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{
		repository:  repository,
		hasher:      hasher,
		identityIDs: identityIDs,
		uuidIDs:     uuidIDs,
		now:         now,
	}, nil
}

func (u *UseCase) Execute(
	ctx context.Context,
	input Input,
) (Output, error) {
	if u == nil ||
		u.repository == nil ||
		u.hasher == nil ||
		u.identityIDs == nil ||
		u.uuidIDs == nil ||
		u.now == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			ErrDependencyMissing,
		)
	}

	if ctx == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("create-identity context is required"),
		)
	}

	if input.ActorID.IsZero() || !input.ActorRole.IsValid() {
		return Output{}, domain.NewError(domain.ErrForbidden)
	}

	targetRole, err := identity.ParseRole(input.Role)
	if err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}

	if !identity.CanCreateRole(input.ActorRole, targetRole) {
		return Output{}, domain.NewError(domain.ErrForbidden)
	}

	email, err := identity.NormalizeAndValidateEmail(input.Email)
	if err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}

	if err := identity.ValidatePassword(input.Password); err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}

	passwordHash, err := u.hasher.Hash(input.Password)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("hash privileged identity password: %w", err),
		)
	}

	identityID, err := u.identityIDs.Generate()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate privileged identity ID: %w", err),
		)
	}

	verificationTokenID, err := u.uuidIDs.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate privileged identity verification token ID: %w", err),
		)
	}

	outboxEventID, err := u.uuidIDs.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate privileged identity outbox event ID: %w", err),
		)
	}

	now := u.now().UTC()
	if now.IsZero() {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("create-identity clock returned zero time"),
		)
	}

	err = u.repository.Create(
		ctx,
		CreateParams{
			IdentityID:          identityID,
			VerificationTokenID: verificationTokenID,
			OutboxEventID:       outboxEventID,
			Email:               email,
			PasswordHash:        passwordHash,
			Role:                targetRole,
			Status:              identity.StatusActive,
			Locale:              domainlocale.Normalize(input.Locale),
			CreatedAt:           now,
			VerificationTokenExpiresAt: now.Add(
				emailVerificationTokenTTL,
			),
			OutboxEventType: emailVerificationEventType,
		},
	)
	if err != nil {
		if errors.Is(err, ErrEmailAlreadyExists) {
			return Output{}, domain.NewError(domain.ErrEmailAlreadyExists)
		}

		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("create privileged identity records: %w", err),
		)
	}

	return Output{
		ID:    identityID,
		Email: email,
		Role:  targetRole,
	}, nil
}
