package login

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	maxRequestIDLength    = 128
	maxUserAgentLength    = 512
	maxLoginPasswordRunes = 128
	loginAuditTimeout     = 3 * time.Second
)

var (
	ErrDependencyMissing = errors.New("login dependency is missing")
	ErrIdentityNotFound  = errors.New("identity was not found")
)

type Input struct {
	Email     string
	Password  string
	IPAddress netip.Addr
	UserAgent string
	RequestID string
}

type User struct {
	ID            identity.ID
	Email         string
	Role          identity.Role
	EmailVerified bool
}

type Output struct {
	AccessToken           string
	RefreshToken          string
	TokenType             string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
	DeviceID              string
	User                  User
}

type Attempt struct {
	ID          string
	IdentityID  *identity.ID
	Email       string
	Success     bool
	FailureCode string
	IPAddress   netip.Addr
	UserAgent   string
	RequestID   string
	AttemptedAt time.Time
}

type Session = appauth.Session

type AccessTokenClaims = appauth.AccessTokenClaims

type RefreshTokenClaims = appauth.RefreshTokenClaims

type Repository interface {
	FindByEmail(
		ctx context.Context,
		email string,
	) (identity.Identity, error)

	RecordAttempt(
		ctx context.Context,
		attempt Attempt,
	) error
}

type PasswordVerifier interface {
	Verify(
		password string,
		encodedHash string,
	) (bool, error)
}

type UUIDGenerator interface {
	GenerateString() (string, error)
}

type RateLimiter interface {
	AllowLoginIP(
		ctx context.Context,
		requestID string,
		ipAddress netip.Addr,
	) (bool, error)

	AllowLoginEmail(
		ctx context.Context,
		requestID string,
		email string,
	) (bool, error)
}

type AccessTokenIssuer interface {
	Issue(
		claims AccessTokenClaims,
	) (token string, expiresAt time.Time, err error)
}

type RefreshTokenEncoder interface {
	Encode(claims appauth.RefreshTokenClaims) (string, error)
}

type SessionStore interface {
	Save(
		ctx context.Context,
		session Session,
	) error

	Delete(
		ctx context.Context,
		userID identity.ID,
		deviceID string,
	) error
}

type UseCase struct {
	repository        Repository
	passwordVerifier  PasswordVerifier
	ids               UUIDGenerator
	rateLimiter       RateLimiter
	accessTokens      AccessTokenIssuer
	refreshTokens     RefreshTokenEncoder
	sessions          SessionStore
	dummyPasswordHash string
	now               func() time.Time
}

func New(
	repository Repository,
	passwordVerifier PasswordVerifier,
	ids UUIDGenerator,
	rateLimiter RateLimiter,
	accessTokens AccessTokenIssuer,
	refreshTokens RefreshTokenEncoder,
	sessions SessionStore,
	dummyPasswordHash string,
	now func() time.Time,
) (*UseCase, error) {
	if repository == nil ||
		passwordVerifier == nil ||
		ids == nil ||
		rateLimiter == nil ||
		accessTokens == nil ||
		refreshTokens == nil ||
		sessions == nil ||
		strings.TrimSpace(dummyPasswordHash) == "" ||
		now == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{
		repository:        repository,
		passwordVerifier:  passwordVerifier,
		ids:               ids,
		rateLimiter:       rateLimiter,
		accessTokens:      accessTokens,
		refreshTokens:     refreshTokens,
		sessions:          sessions,
		dummyPasswordHash: dummyPasswordHash,
		now:               now,
	}, nil
}

func (u *UseCase) Execute(
	ctx context.Context,
	input Input,
) (Output, error) {
	if u == nil ||
		u.repository == nil ||
		u.passwordVerifier == nil ||
		u.ids == nil ||
		u.rateLimiter == nil ||
		u.accessTokens == nil ||
		u.refreshTokens == nil ||
		u.sessions == nil ||
		u.now == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			ErrDependencyMissing,
		)
	}

	if ctx == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("login context is required"),
		)
	}

	now := u.now().UTC().Truncate(time.Second)
	if now.IsZero() {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("login clock returned zero time"),
		)
	}

	if !input.IPAddress.IsValid() ||
		input.RequestID == "" ||
		len(input.RequestID) > maxRequestIDLength ||
		strings.IndexFunc(input.RequestID, unicode.IsSpace) >= 0 {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	userAgent := normalizeUserAgent(input.UserAgent)
	ipAddress := input.IPAddress.Unmap()

	attemptID, err := u.ids.GenerateString()
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("generate login-attempt ID: %w", err),
		)
	}

	attempt := Attempt{
		ID:          attemptID,
		Email:       normalizeAttemptEmail(input.Email),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		RequestID:   input.RequestID,
		AttemptedAt: now,
	}

	ipAllowed, err := u.rateLimiter.AllowLoginIP(
		ctx,
		input.RequestID,
		ipAddress,
	)
	if err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInternal,
			fmt.Errorf("check login IP rate limit: %w", err),
		)
	}

	if !ipAllowed {
		return u.fail(
			ctx,
			attempt,
			domain.ErrRateLimited,
			nil,
		)
	}

	email, err := identity.NormalizeAndValidateEmail(input.Email)
	if err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInvalidInput,
			err,
		)
	}
	attempt.Email = email

	emailAllowed, err := u.rateLimiter.AllowLoginEmail(
		ctx,
		input.RequestID,
		email,
	)
	if err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInternal,
			fmt.Errorf("check login email rate limit: %w", err),
		)
	}

	if !emailAllowed {
		return u.fail(
			ctx,
			attempt,
			domain.ErrRateLimited,
			nil,
		)
	}

	if err := validateAuthenticationPassword(input.Password); err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInvalidInput,
			err,
		)
	}

	account, err := u.repository.FindByEmail(ctx, email)
	if errors.Is(err, ErrIdentityNotFound) {
		if _, verifyErr := u.passwordVerifier.Verify(
			input.Password,
			u.dummyPasswordHash,
		); verifyErr != nil {
			return u.fail(
				ctx,
				attempt,
				domain.ErrInternal,
				fmt.Errorf("verify dummy password hash: %w", verifyErr),
			)
		}

		return u.fail(
			ctx,
			attempt,
			domain.ErrInvalidCredentials,
			nil,
		)
	}

	if err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInternal,
			fmt.Errorf("find identity by email: %w", err),
		)
	}

	attempt.IdentityID = identityIDPointer(account.ID)

	passwordMatches, err := u.passwordVerifier.Verify(
		input.Password,
		account.PasswordHash,
	)
	if err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInternal,
			fmt.Errorf("verify password hash: %w", err),
		)
	}

	if !passwordMatches {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInvalidCredentials,
			nil,
		)
	}

	if err := account.CanAuthenticate(); err != nil {
		var domainError *domain.Error
		if errors.As(err, &domainError) {
			return u.fail(
				ctx,
				attempt,
				domainError.Code,
				domainError.Cause,
			)
		}

		return u.fail(
			ctx,
			attempt,
			domain.ErrInternal,
			fmt.Errorf("check identity authentication state: %w", err),
		)
	}

	deviceID, err := u.ids.GenerateString()
	if err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInternal,
			fmt.Errorf("generate device ID: %w", err),
		)
	}

	refreshTokenID, err := u.ids.GenerateString()
	if err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInternal,
			fmt.Errorf("generate refresh-token ID: %w", err),
		)
	}

	accessTokenJTI, err := u.ids.GenerateString()
	if err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInternal,
			fmt.Errorf("generate access-token JTI: %w", err),
		)
	}

	accessToken, accessExpiresAt, err := u.accessTokens.Issue(
		AccessTokenClaims{
			Subject:       account.ID,
			DeviceID:      deviceID,
			Role:          account.Role,
			EmailVerified: account.EmailVerified,
			IssuedAt:      now,
			JTI:           accessTokenJTI,
		},
	)
	if err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInternal,
			fmt.Errorf("issue access token: %w", err),
		)
	}

	refreshExpiresAt := now.Add(appauth.RefreshTokenTTL)

	refreshToken, err := u.refreshTokens.Encode(
		appauth.RefreshTokenClaims{
			UserID:    account.ID,
			DeviceID:  deviceID,
			TokenID:   refreshTokenID,
			IssuedAt:  now,
			ExpiresAt: refreshExpiresAt,
		},
	)
	if err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInternal,
			fmt.Errorf("encode refresh token: %w", err),
		)
	}

	session := Session{
		Token:      refreshTokenID,
		UserID:     account.ID,
		DeviceID:   deviceID,
		UserAgent:  userAgent,
		IPAddress:  ipAddress,
		CreatedAt:  now,
		ExpiresAt:  refreshExpiresAt,
		LastUsedAt: now,
	}

	if err := u.sessions.Save(ctx, session); err != nil {
		return u.fail(
			ctx,
			attempt,
			domain.ErrInternal,
			fmt.Errorf("save refresh session: %w", err),
		)
	}

	attempt.Success = true
	attempt.FailureCode = ""

	if err := u.recordAttempt(ctx, attempt); err != nil {
		cleanupContext, cancelCleanup := context.WithTimeout(
			context.WithoutCancel(ctx),
			loginAuditTimeout,
		)
		defer cancelCleanup()

		cleanupErr := u.sessions.Delete(
			cleanupContext,
			account.ID,
			deviceID,
		)

		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.Join(
				fmt.Errorf("record successful login attempt: %w", err),
				cleanupErr,
			),
		)
	}

	return Output{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		TokenType:             "Bearer",
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshTokenExpiresAt: refreshExpiresAt,
		DeviceID:              deviceID,
		User: User{
			ID:            account.ID,
			Email:         account.Email,
			Role:          account.Role,
			EmailVerified: account.EmailVerified,
		},
	}, nil
}

func (u *UseCase) fail(
	ctx context.Context,
	attempt Attempt,
	code domain.ErrorCode,
	cause error,
) (Output, error) {
	attempt.Success = false
	attempt.FailureCode = string(code)

	if err := u.recordAttempt(ctx, attempt); err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.Join(
				cause,
				fmt.Errorf("record failed login attempt: %w", err),
			),
		)
	}

	if code == domain.ErrInternal {
		if cause == nil {
			cause = errors.New("internal login failure")
		}

		return Output{}, domain.WrapError(code, cause)
	}

	if cause != nil {
		return Output{}, domain.WrapError(code, cause)
	}

	return Output{}, domain.NewError(code)
}

func (u *UseCase) recordAttempt(
	ctx context.Context,
	attempt Attempt,
) error {
	auditContext, cancelAudit := context.WithTimeout(
		context.WithoutCancel(ctx),
		loginAuditTimeout,
	)
	defer cancelAudit()

	return u.repository.RecordAttempt(
		auditContext,
		attempt,
	)
}

func validateAuthenticationPassword(password string) error {
	if password == "" {
		return errors.New("password is required")
	}

	if !utf8.ValidString(password) {
		return errors.New("password contains invalid UTF-8")
	}

	if utf8.RuneCountInString(password) > maxLoginPasswordRunes {
		return errors.New("password exceeds maximum length")
	}

	return nil
}

func normalizeAttemptEmail(rawEmail string) string {
	normalized := strings.ToLower(strings.TrimSpace(rawEmail))

	normalized = strings.Map(
		func(character rune) rune {
			if unicode.IsControl(character) {
				return -1
			}

			return character
		},
		normalized,
	)

	if normalized == "" {
		normalized = "<empty>"
	}

	runes := []rune(normalized)
	if len(runes) > 254 {
		normalized = string(runes[:254])
	}

	return normalized
}

func normalizeUserAgent(rawUserAgent string) string {
	userAgent := strings.TrimSpace(rawUserAgent)
	if userAgent == "" {
		return "unknown"
	}

	runes := []rune(userAgent)
	if len(runes) > maxUserAgentLength {
		return string(runes[:maxUserAgentLength])
	}

	return userAgent
}

func identityIDPointer(value identity.ID) *identity.ID {
	copyValue := value
	return &copyValue
}
