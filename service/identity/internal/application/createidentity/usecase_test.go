package createidentity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	testActorID  = identity.ID("0198f124-659f-7cbd-a441-dc7eea175073")
	testNewID    = identity.ID("0198f124-659f-7cbd-a441-dc7eea175074")
	testTokenID  = "0198f124-659f-7cbd-a441-dc7eea175075"
	testOutboxID = "0198f124-659f-7cbd-a441-dc7eea175076"
)

var createIdentityTestNow = time.Date(
	2026,
	time.July,
	31,
	1,
	0,
	0,
	0,
	time.UTC,
)

func TestUseCaseAdminCreatesViceAdmin(t *testing.T) {
	t.Parallel()

	var persisted CreateParams
	useCase := newUseCase(
		t,
		&fakeRepository{
			create: func(_ context.Context, params CreateParams) error {
				persisted = params
				return nil
			},
		},
		&fakeHasher{hash: "$argon2id$test"},
	)

	output, err := useCase.Execute(
		context.Background(),
		Input{
			ActorID:   testActorID,
			ActorRole: identity.RoleAdmin,
			Email:     " ViceAdmin@Example.COM ",
			Password:  "Secure1!",
			Role:      "vice_admin",
			Locale:    "ja-JP",
		},
	)
	if err != nil {
		t.Fatalf("execute create identity: %v", err)
	}

	if output.ID != testNewID ||
		output.Email != "viceadmin@example.com" ||
		output.Role != identity.RoleViceAdmin {
		t.Fatalf("unexpected output: %+v", output)
	}

	if persisted.IdentityID != testNewID ||
		persisted.VerificationTokenID != testTokenID ||
		persisted.OutboxEventID != testOutboxID ||
		persisted.Role != identity.RoleViceAdmin ||
		persisted.Status != identity.StatusActive ||
		persisted.Locale != "ja" ||
		persisted.PasswordHash != "$argon2id$test" ||
		persisted.OutboxEventType != emailVerificationEventType {
		t.Fatalf("unexpected persistence params: %+v", persisted)
	}

	if !persisted.CreatedAt.Equal(createIdentityTestNow) {
		t.Fatalf("unexpected created_at %s", persisted.CreatedAt)
	}

	if !persisted.VerificationTokenExpiresAt.Equal(createIdentityTestNow.Add(time.Hour)) {
		t.Fatalf(
			"unexpected verification expiry %s",
			persisted.VerificationTokenExpiresAt,
		)
	}
}

func TestUseCaseRoleHierarchy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		actorRole identity.Role
		target    string
		allowed   bool
	}{
		{name: "admin creates agency", actorRole: identity.RoleAdmin, target: "AGENCY", allowed: true},
		{name: "admin creates vice admin", actorRole: identity.RoleAdmin, target: "VICE_ADMIN", allowed: true},
		{name: "vice admin creates agency", actorRole: identity.RoleViceAdmin, target: "AGENCY", allowed: true},
		{name: "vice admin cannot create vice admin", actorRole: identity.RoleViceAdmin, target: "VICE_ADMIN"},
		{name: "admin cannot create admin", actorRole: identity.RoleAdmin, target: "ADMIN"},
		{name: "admin cannot create client", actorRole: identity.RoleAdmin, target: "CLIENT"},
		{name: "client cannot create agency", actorRole: identity.RoleClient, target: "AGENCY"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			repositoryCalled := false
			useCase := newUseCase(
				t,
				&fakeRepository{
					create: func(context.Context, CreateParams) error {
						repositoryCalled = true
						return nil
					},
				},
				&fakeHasher{hash: "$argon2id$test"},
			)

			_, err := useCase.Execute(
				context.Background(),
				Input{
					ActorID:   testActorID,
					ActorRole: test.actorRole,
					Email:     "created@example.com",
					Password:  "Secure1!",
					Role:      test.target,
					Locale:    "en",
				},
			)

			if test.allowed {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				if !repositoryCalled {
					t.Fatal("expected repository to be called")
				}
				return
			}

			assertDomainCode(t, err, domain.ErrForbidden)
			if repositoryCalled {
				t.Fatal("repository must not run for forbidden hierarchy")
			}
		})
	}
}

func TestUseCaseRejectsUnknownRoleAsInvalidInput(t *testing.T) {
	t.Parallel()

	useCase := newUseCase(
		t,
		&fakeRepository{create: func(context.Context, CreateParams) error { return nil }},
		&fakeHasher{hash: "$argon2id$test"},
	)

	_, err := useCase.Execute(
		context.Background(),
		Input{
			ActorID:   testActorID,
			ActorRole: identity.RoleAdmin,
			Email:     "created@example.com",
			Password:  "Secure1!",
			Role:      "SUPER_ADMIN",
		},
	)

	assertDomainCode(t, err, domain.ErrInvalidInput)
}

func TestUseCaseMapsEmailConflict(t *testing.T) {
	t.Parallel()

	useCase := newUseCase(
		t,
		&fakeRepository{
			create: func(context.Context, CreateParams) error {
				return ErrEmailAlreadyExists
			},
		},
		&fakeHasher{hash: "$argon2id$test"},
	)

	_, err := useCase.Execute(
		context.Background(),
		Input{
			ActorID:   testActorID,
			ActorRole: identity.RoleAdmin,
			Email:     "created@example.com",
			Password:  "Secure1!",
			Role:      "AGENCY",
		},
	)

	assertDomainCode(t, err, domain.ErrEmailAlreadyExists)
}

func newUseCase(
	t *testing.T,
	repository Repository,
	hasher PasswordHasher,
) *UseCase {
	t.Helper()

	ids := &fakeIDs{
		identityID: testNewID,
		uuids: []string{
			testTokenID,
			testOutboxID,
		},
	}

	useCase, err := New(
		repository,
		hasher,
		ids,
		ids,
		func() time.Time { return createIdentityTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	return useCase
}

func assertDomainCode(
	t *testing.T,
	err error,
	expected domain.ErrorCode,
) {
	t.Helper()

	var domainError *domain.Error
	if !errors.As(err, &domainError) {
		t.Fatalf("expected domain error, got %v", err)
	}

	if domainError.Code != expected {
		t.Fatalf("expected %q, got %q", expected, domainError.Code)
	}
}

type fakeRepository struct {
	create func(context.Context, CreateParams) error
}

func (f *fakeRepository) Create(
	ctx context.Context,
	params CreateParams,
) error {
	return f.create(ctx, params)
}

type fakeHasher struct {
	hash string
	err  error
}

func (f *fakeHasher) Hash(string) (string, error) {
	return f.hash, f.err
}

type fakeIDs struct {
	identityID identity.ID
	uuids      []string
	index      int
}

func (f *fakeIDs) Generate() (identity.ID, error) {
	return f.identityID, nil
}

func (f *fakeIDs) GenerateString() (string, error) {
	if f.index >= len(f.uuids) {
		return "", errors.New("no UUID configured")
	}

	value := f.uuids[f.index]
	f.index++
	return value, nil
}
