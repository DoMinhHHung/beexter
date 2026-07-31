package loginhistory

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	defaultLimit = 25
	maxLimit     = 100
)

var (
	ErrDependencyMissing = errors.New("login-history dependency is missing")
	ErrIdentityNotFound  = errors.New("login-history identity was not found")
)

type Input struct {
	UserID identity.ID
	Limit  int
	Before *time.Time
}

type Attempt struct {
	ID          string
	Success     bool
	FailureCode string
	IPAddress   netip.Addr
	UserAgent   string
	AttemptedAt time.Time
}

type Output struct {
	Attempts   []Attempt
	NextBefore *time.Time
}

type Repository interface {
	List(
		ctx context.Context,
		identityID identity.ID,
		limit int,
		before *time.Time,
	) ([]Attempt, error)
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

func (u *UseCase) Execute(ctx context.Context, input Input) (Output, error) {
	if u == nil || u.repository == nil {
		return Output{}, domain.WrapError(domain.ErrInternal, ErrDependencyMissing)
	}
	if ctx == nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			errors.New("login-history context is required"),
		)
	}
	if input.UserID.IsZero() || input.Limit < 0 || input.Limit > maxLimit {
		return Output{}, domain.NewError(domain.ErrInvalidInput)
	}

	limit := input.Limit
	if limit == 0 {
		limit = defaultLimit
	}

	var before *time.Time
	if input.Before != nil {
		normalized := input.Before.UTC()
		if normalized.IsZero() {
			return Output{}, domain.NewError(domain.ErrInvalidInput)
		}
		before = &normalized
	}

	attempts, err := u.repository.List(ctx, input.UserID, limit+1, before)
	if errors.Is(err, ErrIdentityNotFound) {
		return Output{}, domain.NewError(domain.ErrTokenInvalid)
	}
	if err != nil {
		return Output{}, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("list login history: %w", err),
		)
	}

	var nextBefore *time.Time
	if len(attempts) > limit {
		attempts = attempts[:limit]
		cursor := attempts[len(attempts)-1].AttemptedAt.UTC()
		nextBefore = &cursor
	}

	return Output{Attempts: attempts, NextBefore: nextBefore}, nil
}
