package getme

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

var (
	ErrDependencyMissing = errors.New("get-me dependency is missing")
	ErrIdentityNotFound  = errors.New("identity was not found")
)

type Input struct {
	UserID identity.ID
}

type Output struct {
	ID            identity.ID
	Email         string
	Role          identity.Role
	Status        identity.Status
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Repository interface {
	FindByID(ctx context.Context, userID identity.ID) (identity.Identity, error)
}

type UseCase struct {
	repository Repository
}

func New(repository Repository) (*UseCase, error) {
	if repository == nil {
		return nil, ErrDependencyMissing
	}

	return &UseCase{repository: repository}, nil
}

func (u *UseCase) Execute(
	ctx context.Context,
	input Input,
) (Output, error) {
	if u == nil || u.repository == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			ErrDependencyMissing,
		)
	}
	if ctx == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("get-me context is required"),
		)
	}
	if input.UserID.IsZero() {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	account, err := u.repository.FindByID(ctx, input.UserID)
	if errors.Is(err, ErrIdentityNotFound) {
		return Output{}, domain.NewError(domain.ErrNotFound)
	}
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("find current identity: %w", err),
		)
	}

	if account.ID != input.UserID {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("current identity does not match requested identity"),
		)
	}

	if err := account.CanAuthenticate(); err != nil {
		var domainError *domain.Error
		if errors.As(err, &domainError) {
			return Output{}, domain.NewError(domainError.Code)
		}
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("check current identity state: %w", err),
		)
	}

	return Output{
		ID:            account.ID,
		Email:         account.Email,
		Role:          account.Role,
		Status:        account.Status,
		EmailVerified: account.EmailVerified,
		CreatedAt:     account.CreatedAt.UTC(),
		UpdatedAt:     account.UpdatedAt.UTC(),
	}, nil
}
