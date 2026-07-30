package forgotpassword

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
	passwordResetTokenTTL  = time.Hour
	passwordResetEventType = "identity.password_reset_requested"
	maxRequestIDLength     = 128
)

var ErrDependencyMissing = errors.New(
	"forgot-password dependency is missing",
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
	Email                       string
	PasswordResetTokenID        string
	OutboxEventID               string
	Locale                      string
	CreatedAt                   time.Time
	PasswordResetTokenExpiresAt time.Time
	OutboxEventType             string
}

type Repository interface {
	RequestReset(
		ctx context.Context,
		params CreateParams,
	) error
}

type UUIDGenerator interface {
	GenerateString() (string, error)
}

type RateLimiter interface {
	AllowForgotPasswordIP(
		ctx context.Context,
		requestID string,
		ipAddress netip.Addr,
	) (bool, error)

	AllowForgotPasswordEmail(
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
			errors.New("forgot-password context is required"),
		)
	}

	if !input.IPAddress.IsValid() ||
		input.RequestID == "" ||
		len(input.RequestID) > maxRequestIDLength ||
		strings.IndexFunc(input.RequestID, unicode.IsSpace) >= 0 {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	ipAddress := input.IPAddress.Unmap()
	ipAllowed, err := u.rateLimiter.AllowForgotPasswordIP(
		ctx,
		input.RequestID,
		ipAddress,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check forgot-password IP rate limit: %w", err),
		)
	}

	if !ipAllowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	email, err := identity.NormalizeAndValidateEmail(input.Email)
	if err != nil {
		return Output{}, domain.WrapError(domain.ErrInvalidInput, err)
	}

	emailAllowed, err := u.rateLimiter.AllowForgotPasswordEmail(
		ctx,
		input.RequestID,
		email,
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check forgot-password email rate limit: %w", err),
		)
	}

	if !emailAllowed {
		return Output{}, domain.NewError(domain.ErrRateLimited)
	}

	passwordResetTokenID, err := u.ids.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate password-reset token ID: %w", err),
		)
	}

	outboxEventID, err := u.ids.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate password-reset outbox event ID: %w", err),
		)
	}

	now := u.now().UTC()
	if now.IsZero() {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("forgot-password clock returned zero time"),
		)
	}

	err = u.repository.RequestReset(
		ctx,
		CreateParams{
			Email:                email,
			PasswordResetTokenID: passwordResetTokenID,
			OutboxEventID:        outboxEventID,
			Locale:               domainlocale.Normalize(input.Locale),
			CreatedAt:            now,
			PasswordResetTokenExpiresAt: now.Add(
				passwordResetTokenTTL,
			),
			OutboxEventType: passwordResetEventType,
		},
	)
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("create password-reset request: %w", err),
		)
	}

	return Output{Accepted: true}, nil
}
