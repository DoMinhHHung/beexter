package resendverification

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
	verificationTokenTTL       = time.Hour
	emailVerificationEventType = "identity.email_verification_requested"
	maxRequestIDLength         = 128
)

var ErrDependencyMissing = errors.New(
	"resend-verification dependency is missing",
)

type Input struct {
	Email     string
	Locale    string
	IPAddress netip.Addr
	RequestID string
}

type Output struct {
	Accepted bool
}

type CreateParams struct {
	Email                      string
	VerificationTokenID        string
	OutboxEventID              string
	Locale                     string
	CreatedAt                  time.Time
	VerificationTokenExpiresAt time.Time
	OutboxEventType            string
}

type Repository interface {
	Resend(ctx context.Context, params CreateParams) error
}

type UUIDGenerator interface {
	GenerateString() (string, error)
}

type RateLimiter interface {
	AllowResendVerificationIP(
		ctx context.Context,
		requestID string,
		ipAddress netip.Addr,
	) (bool, error)

	AllowResendVerificationEmail(
		ctx context.Context,
		requestID string,
		email string,
	) (bool, error)
}

type UseCase struct {
	repository  Repository
	ids         UUIDGenerator
	rateLimiter RateLimiter
	now         func() time.Time
}

func New(
	repository Repository,
	ids UUIDGenerator,
	rateLimiter RateLimiter,
	now func() time.Time,
) (*UseCase, error) {
	if repository == nil || ids == nil || rateLimiter == nil || now == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{
		repository:  repository,
		ids:         ids,
		rateLimiter: rateLimiter,
		now:         now,
	}, nil
}

func (u *UseCase) Execute(
	ctx context.Context,
	input Input,
) (Output, error) {
	if u == nil ||
		u.repository == nil ||
		u.ids == nil ||
		u.rateLimiter == nil ||
		u.now == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			ErrDependencyMissing,
		)
	}

	if ctx == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("resend-verification context is required"),
		)
	}

	if !input.IPAddress.IsValid() ||
		input.RequestID == "" ||
		len(input.RequestID) > maxRequestIDLength ||
		strings.IndexFunc(input.RequestID, unicode.IsSpace) >= 0 {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	ipAddress := input.IPAddress.Unmap()
	ipAllowed, err := u.rateLimiter.AllowResendVerificationIP(
		ctx,
		input.RequestID,
		ipAddress,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check resend-verification IP rate limit: %w", err),
		)
	}

	if !ipAllowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	email, err := identity.NormalizeAndValidateEmail(input.Email)
	if err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}

	emailAllowed, err := u.rateLimiter.AllowResendVerificationEmail(
		ctx,
		input.RequestID,
		email,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check resend-verification email rate limit: %w", err),
		)
	}

	if !emailAllowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	verificationTokenID, err := u.ids.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate verification token ID: %w", err),
		)
	}

	outboxEventID, err := u.ids.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate verification outbox event ID: %w", err),
		)
	}

	now := u.now().UTC()
	if now.IsZero() {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("resend-verification clock returned zero time"),
		)
	}

	err = u.repository.Resend(
		ctx,
		CreateParams{
			Email:               email,
			VerificationTokenID: verificationTokenID,
			OutboxEventID:       outboxEventID,
			Locale:              domainlocale.Normalize(input.Locale),
			CreatedAt:           now,
			VerificationTokenExpiresAt: now.Add(
				verificationTokenTTL,
			),
			OutboxEventType: emailVerificationEventType,
		},
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("create verification resend request: %w", err),
		)
	}

	return Output{Accepted: true}, nil
}
