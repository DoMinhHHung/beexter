package signup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	domainlocale "github.com/DoMinhHHung/beexter/service/identity/internal/domain/locale"
)

const (
	emailVerificationTokenTTL  = time.Hour
	emailVerificationEventType = "identity.email_verification_requested"
	maxRequestIDLength         = 128
)

var (
	ErrDependencyMissing  = errors.New("signup dependency is missing")
	ErrEmailAlreadyExists = errors.New("email already exists")
)

type Input struct {
	Email     string
	Password  string
	Locale    string
	IPAddress netip.Addr
	RequestID string
}

type Output struct {
	ID    identity.ID
	Email string
}

type CreateParams struct {
	IdentityID                 identity.ID
	VerificationTokenID        string
	OutboxEventID              string
	Email                      string
	PasswordHash               string
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

type RateLimiter interface {
	AllowSignupIP(
		ctx context.Context,
		requestID string,
		ipAddress netip.Addr,
	) (bool, error)

	AllowSignupEmail(
		ctx context.Context,
		requestID string,
		email string,
	) (bool, error)
}

type UseCase struct {
	repository  Repository
	hasher      PasswordHasher
	identityIDs IdentityIDGenerator
	uuidIDs     UUIDGenerator
	rateLimiter RateLimiter
	now         func() time.Time
}

func New(
	repository Repository,
	hasher PasswordHasher,
	identityIDs IdentityIDGenerator,
	uuidIDs UUIDGenerator,
	rateLimiter RateLimiter,
	now func() time.Time,
) (*UseCase, error) {
	if repository == nil ||
		hasher == nil ||
		identityIDs == nil ||
		uuidIDs == nil ||
		rateLimiter == nil ||
		now == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{
		repository:  repository,
		hasher:      hasher,
		identityIDs: identityIDs,
		uuidIDs:     uuidIDs,
		rateLimiter: rateLimiter,
		now:         now,
	}, nil
}

func (u *UseCase) Execute(
	ctx context.Context,
	input Input,
) (Output, error) {
	if u == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			ErrDependencyMissing,
		)
	}

	if ctx == nil {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	if !input.IPAddress.IsValid() ||
		input.RequestID == "" ||
		len(input.RequestID) > maxRequestIDLength ||
		strings.IndexFunc(input.RequestID, unicode.IsSpace) >= 0 {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	ipAddress := input.IPAddress.Unmap()

	ipAllowed, err := u.rateLimiter.AllowSignupIP(
		ctx,
		input.RequestID,
		ipAddress,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check signup IP rate limit: %w", err),
		)
	}

	if !ipAllowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	email, err := identity.NormalizeAndValidateEmail(input.Email)
	if err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}

	emailAllowed, err := u.rateLimiter.AllowSignupEmail(
		ctx,
		input.RequestID,
		email,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check signup email rate limit: %w", err),
		)
	}

	if !emailAllowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	if err := identity.ValidatePassword(input.Password); err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}

	passwordHash, err := u.hasher.Hash(input.Password)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("hash password: %w", err),
		)
	}

	identityID, err := u.identityIDs.Generate()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate identity ID: %w", err),
		)
	}

	verificationTokenID, err := u.uuidIDs.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate verification token ID: %w", err),
		)
	}

	outboxEventID, err := u.uuidIDs.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate outbox event ID: %w", err),
		)
	}

	now := u.now().UTC()
	if now.IsZero() {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("clock returned zero time"),
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
			fmt.Errorf("create signup records: %w", err),
		)
	}

	return Output{ID: identityID, Email: email}, nil
}
