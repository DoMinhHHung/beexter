package getme

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const getMeTestUserID = identity.ID("0198f124-659f-7cbd-a441-dc7eea175073")

func TestUseCaseReturnsCurrentIdentity(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	updatedAt := createdAt.Add(time.Hour)
	repository := &stubRepository{
		findByID: func(
			_ context.Context,
			userID identity.ID,
		) (identity.Identity, error) {
			if userID != getMeTestUserID {
				t.Fatalf("unexpected user ID %q", userID)
			}
			return identity.Identity{
				ID:            getMeTestUserID,
				Email:         "user@example.com",
				PlatformRole:  identity.PlatformRoleAdmin,
				Status:        identity.StatusActive,
				EmailVerified: true,
				CreatedAt:     createdAt,
				UpdatedAt:     updatedAt,
			}, nil
		},
	}

	useCase, err := New(repository)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	output, err := useCase.Execute(
		context.Background(),
		Input{UserID: getMeTestUserID},
	)
	if err != nil {
		t.Fatalf("execute get-me: %v", err)
	}

	if output.ID != getMeTestUserID ||
		output.Email != "user@example.com" ||
		output.PlatformRole != identity.PlatformRoleAdmin ||
		output.Status != identity.StatusActive ||
		!output.EmailVerified ||
		!output.CreatedAt.Equal(createdAt) ||
		!output.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("unexpected output: %+v", output)
	}
}

func TestUseCaseMapsMissingIdentity(t *testing.T) {
	t.Parallel()

	useCase, err := New(&stubRepository{
		findByID: func(
			context.Context,
			identity.ID,
		) (identity.Identity, error) {
			return identity.Identity{}, ErrIdentityNotFound
		},
	})
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	_, err = useCase.Execute(
		context.Background(),
		Input{UserID: getMeTestUserID},
	)

	var domainError *domain.Error
	if !errors.As(err, &domainError) || domainError.Code != domain.ErrNotFound {
		t.Fatalf("expected ERR_NOT_FOUND, got %v", err)
	}
}

func TestUseCaseRejectsInactiveIdentity(t *testing.T) {
	t.Parallel()

	useCase, err := New(&stubRepository{
		findByID: func(
			context.Context,
			identity.ID,
		) (identity.Identity, error) {
			return identity.Identity{
				ID:            getMeTestUserID,
				Email:         "user@example.com",
				PlatformRole:  identity.PlatformRoleNone,
				Status:        identity.StatusInactive,
				EmailVerified: true,
				CreatedAt:     time.Now().UTC().Add(-time.Hour),
				UpdatedAt:     time.Now().UTC(),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	_, err = useCase.Execute(
		context.Background(),
		Input{UserID: getMeTestUserID},
	)

	var domainError *domain.Error
	if !errors.As(err, &domainError) || domainError.Code != domain.ErrAccountInactive {
		t.Fatalf("expected ERR_ACCOUNT_INACTIVE, got %v", err)
	}
}

type stubRepository struct {
	findByID func(context.Context, identity.ID) (identity.Identity, error)
}

func (s *stubRepository) FindByID(
	ctx context.Context,
	userID identity.ID,
) (identity.Identity, error) {
	return s.findByID(ctx, userID)
}
