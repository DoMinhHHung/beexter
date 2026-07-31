package requestreactivation

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	domainlocale "github.com/DoMinhHHung/beexter/service/identity/internal/domain/locale"
)

const (
	verificationTokenTTL  = time.Hour
	verificationEventType = "identity.email_verification_requested"
	maxRequestIDLength    = 128
	maxPasswordRunes      = 128
)

var (
	ErrDependencyMissing = errors.New("request-reactivation dependency is missing")
	ErrIdentityNotFound  = errors.New("reactivation identity was not found")
	ErrNotEligible       = errors.New("identity is not eligible for reactivation")
	ErrStateChanged      = errors.New("reactivation identity state changed concurrently")
)

type Input struct {
	Email     string
	Password  string
	Locale    string
	IPAddress netip.Addr
	RequestID string
}

type Output struct {
	Accepted bool
}

type Candidate struct {
	IdentityID      identity.ID
	PasswordHash    string
	Status          identity.Status
	DeletedAt       *time.Time
	SoftDeleteCount uint8
}

type CreateParams struct {
	IdentityID           identity.ID
	ExpectedPasswordHash string
	VerificationTokenID  string
	OutboxEventID        string
	Locale               string
	CreatedAt            time.Time
	ExpiresAt            time.Time
	EventType            string
}

type Repository interface {
	FindByEmail(ctx context.Context, email string) (Candidate, error)
	Request(ctx context.Context, params CreateParams) error
}

type PasswordVerifier interface {
	Verify(password string, encodedHash string) (bool, error)
}

type UUIDGenerator interface {
	GenerateString() (string, error)
}

type RateLimiter interface {
	AllowReactivationIP(
		ctx context.Context,
		requestID string,
		ipAddress netip.Addr,
	) (bool, error)
	AllowReactivationEmail(
		ctx context.Context,
		requestID string,
		email string,
	) (bool, error)
}

type UseCase struct {
	repository Repository
	passwords  PasswordVerifier
	ids        UUIDGenerator
	limiter    RateLimiter
	dummyHash  string
	now        func() time.Time
}

func New(
	repository Repository,
	passwords PasswordVerifier,
	ids UUIDGenerator,
	limiter RateLimiter,
	dummyHash string,
	now func() time.Time,
) (*UseCase, error) {
	if repository == nil || passwords == nil || ids == nil || limiter == nil ||
		strings.TrimSpace(dummyHash) == "" || now == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{
		repository: repository,
		passwords:  passwords,
		ids:        ids,
		limiter:    limiter,
		dummyHash:  dummyHash,
		now:        now,
	}, nil
}

func (u *UseCase) Execute(ctx context.Context, input Input) (Output, error) {
	if u == nil || u.repository == nil || u.passwords == nil || u.ids == nil ||
		u.limiter == nil || u.dummyHash == "" || u.now == nil {
		return Output{}, domain.WrapError(domain.ErrInternal, ErrDependencyMissing)
	}
	if ctx == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("request-reactivation context is required"),
		)
	}
	if !input.IPAddress.IsValid() || input.RequestID == "" ||
		len(input.RequestID) > maxRequestIDLength ||
		strings.IndexFunc(input.RequestID, unicode.IsSpace) >= 0 {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	allowed, err := u.limiter.AllowReactivationIP(
		ctx,
		input.RequestID,
		input.IPAddress.Unmap(),
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check reactivation IP rate limit: %w", err),
		)
	}
	if !allowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	email, err := identity.NormalizeAndValidateEmail(input.Email)
	if err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}
	if err := validatePasswordInput(input.Password); err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}

	allowed, err = u.limiter.AllowReactivationEmail(
		ctx,
		input.RequestID,
		email,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check reactivation email rate limit: %w", err),
		)
	}
	if !allowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	candidate, findErr := u.repository.FindByEmail(ctx, email)
	if findErr != nil && !errors.Is(findErr, ErrIdentityNotFound) {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("find reactivation identity: %w", findErr),
		)
	}

	hashToVerify := u.dummyHash
	eligible := findErr == nil && candidate.Status == identity.StatusInactive &&
		candidate.DeletedAt != nil && !candidate.IdentityID.IsZero()
	if eligible {
		hashToVerify = candidate.PasswordHash
	}

	matches, err := u.passwords.Verify(input.Password, hashToVerify)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("verify reactivation password: %w", err),
		)
	}
	if !eligible || !matches {
		return Output{Accepted: true}, nil
	}

	tokenID, err := u.ids.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate reactivation verification token: %w", err),
		)
	}
	outboxID, err := u.ids.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate reactivation outbox event ID: %w", err),
		)
	}

	createdAt := u.now().UTC().Truncate(time.Second)
	if createdAt.IsZero() {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("request-reactivation clock returned zero time"),
		)
	}

	err = u.repository.Request(
		ctx,
		CreateParams{
			IdentityID:           candidate.IdentityID,
			ExpectedPasswordHash: candidate.PasswordHash,
			VerificationTokenID:  tokenID,
			OutboxEventID:        outboxID,
			Locale:               domainlocale.Normalize(input.Locale),
			CreatedAt:            createdAt,
			ExpiresAt:            createdAt.Add(verificationTokenTTL),
			EventType:            verificationEventType,
		},
	)
	if errors.Is(err, ErrNotEligible) || errors.Is(err, ErrStateChanged) ||
		errors.Is(err, ErrIdentityNotFound) {
		return Output{Accepted: true}, nil
	}
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("create reactivation request: %w", err),
		)
	}

	return Output{Accepted: true}, nil
}

func validatePasswordInput(password string) error {
	if password == "" {
		return errors.New("password is required")
	}
	if !utf8.ValidString(password) {
		return errors.New("password contains invalid UTF-8")
	}
	if utf8.RuneCountInString(password) > maxPasswordRunes {
		return errors.New("password exceeds maximum length")
	}
	return nil
}
