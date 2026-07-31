package refresh

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const (
	testUserID = identity.ID(
		"0198f124-659f-7cbd-a441-dc7eea175073",
	)
	testDeviceID       = "0198f124-659f-7cbd-a441-dc7eea175074"
	testPresentedID    = "0198f124-659f-7cbd-a441-dc7eea175075"
	testReplacementID  = "0198f124-659f-7cbd-a441-dc7eea175076"
	testAccessTokenJTI = "0198f124-659f-7cbd-a441-dc7eea175077"
)

var refreshTestNow = time.Date(
	2026,
	time.July,
	30,
	12,
	0,
	0,
	0,
	time.UTC,
)

func TestUseCaseRotatesRefreshToken(t *testing.T) {
	t.Parallel()

	var receivedRotation appauth.Rotation

	useCase := newTestUseCase(
		t,
		&fakeRepository{account: validAccount()},
		&fakeCodec{},
		&fakeAccessTokenIssuer{},
		&fakeSessionStore{
			rotate: func(rotation appauth.Rotation) error {
				receivedRotation = rotation
				return nil
			},
		},
	)

	output, err := useCase.Execute(
		context.Background(),
		validInput(),
	)
	if err != nil {
		t.Fatalf("execute refresh: %v", err)
	}

	if output.AccessToken != "new-access-token" ||
		output.RefreshToken != "new-refresh-token" ||
		output.DeviceID != testDeviceID {
		t.Fatalf("unexpected output: %+v", output)
	}

	if receivedRotation.PresentedTokenID != testPresentedID ||
		receivedRotation.ReplacementTokenID != testReplacementID ||
		!receivedRotation.ExpiresAt.Equal(
			refreshTestNow.Add(appauth.RefreshTokenTTL),
		) {
		t.Fatalf("unexpected rotation: %+v", receivedRotation)
	}
}

func TestUseCaseMapsExpiredToken(t *testing.T) {
	t.Parallel()

	useCase := newTestUseCase(
		t,
		&fakeRepository{},
		&fakeCodec{decodeErr: appauth.ErrRefreshTokenExpired},
		&fakeAccessTokenIssuer{},
		&fakeSessionStore{},
	)

	_, err := useCase.Execute(context.Background(), validInput())
	assertDomainCode(t, err, domain.ErrTokenExpired)
}

func TestUseCaseMapsReuseAndReliesOnAtomicRevocation(t *testing.T) {
	t.Parallel()

	useCase := newTestUseCase(
		t,
		&fakeRepository{account: validAccount()},
		&fakeCodec{},
		&fakeAccessTokenIssuer{},
		&fakeSessionStore{
			rotate: func(appauth.Rotation) error {
				return appauth.ErrRefreshTokenReuse
			},
		},
	)

	_, err := useCase.Execute(context.Background(), validInput())
	assertDomainCode(t, err, domain.ErrTokenReuseDetected)
}

func TestUseCaseRevokesAllForInactiveAccount(t *testing.T) {
	t.Parallel()

	account := validAccount()
	account.Status = identity.StatusInactive

	revoked := false
	useCase := newTestUseCase(
		t,
		&fakeRepository{account: account},
		&fakeCodec{},
		&fakeAccessTokenIssuer{},
		&fakeSessionStore{
			revokeAll: func(identity.ID) error {
				revoked = true
				return nil
			},
		},
	)

	_, err := useCase.Execute(context.Background(), validInput())
	assertDomainCode(t, err, domain.ErrAccountInactive)

	if !revoked {
		t.Fatal("expected all sessions to be revoked")
	}
}

func newTestUseCase(
	t *testing.T,
	repository Repository,
	codec RefreshTokenCodec,
	issuer AccessTokenIssuer,
	sessions SessionStore,
) *UseCase {
	t.Helper()

	useCase, err := New(
		repository,
		codec,
		issuer,
		sessions,
		&fakeUUIDGenerator{values: []string{
			testReplacementID,
			testAccessTokenJTI,
		}},
		func() time.Time { return refreshTestNow },
	)
	if err != nil {
		t.Fatalf("create use case: %v", err)
	}

	return useCase
}

func validInput() Input {
	return Input{
		RefreshToken: "presented-refresh-token",
		IPAddress:    netip.MustParseAddr("192.0.2.10"),
		UserAgent:    "test-agent",
	}
}

func validAccount() identity.Identity {
	return identity.Identity{
		ID:            testUserID,
		Email:         "user@example.com",
		Role:          identity.RoleClient,
		Status:        identity.StatusActive,
		EmailVerified: true,
	}
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
		t.Fatalf("expected code %q, got %q", expected, domainError.Code)
	}
}

type fakeRepository struct {
	account identity.Identity
	err     error
}

func (f *fakeRepository) FindByID(
	context.Context,
	identity.ID,
) (identity.Identity, error) {
	return f.account, f.err
}

type fakeCodec struct {
	decodeErr error
	encodeErr error
}

func (f *fakeCodec) Decode(
	string,
	time.Time,
) (appauth.RefreshTokenClaims, error) {
	if f.decodeErr != nil {
		return appauth.RefreshTokenClaims{}, f.decodeErr
	}

	return appauth.RefreshTokenClaims{
		UserID:    testUserID,
		DeviceID:  testDeviceID,
		TokenID:   testPresentedID,
		IssuedAt:  refreshTestNow.Add(-time.Hour),
		ExpiresAt: refreshTestNow.Add(appauth.RefreshTokenTTL - time.Hour),
	}, nil
}

func (f *fakeCodec) Encode(
	claims appauth.RefreshTokenClaims,
) (string, error) {
	if f.encodeErr != nil {
		return "", f.encodeErr
	}

	if claims.TokenID != testReplacementID {
		return "", errors.New("unexpected replacement token ID")
	}

	return "new-refresh-token", nil
}

type fakeAccessTokenIssuer struct{}

func (*fakeAccessTokenIssuer) Issue(
	claims appauth.AccessTokenClaims,
) (string, time.Time, error) {
	if claims.DeviceID != testDeviceID ||
		claims.JTI != testAccessTokenJTI {
		return "", time.Time{}, errors.New("unexpected access-token JTI")
	}

	return "new-access-token", refreshTestNow.Add(time.Hour), nil
}

type fakeSessionStore struct {
	rotate    func(appauth.Rotation) error
	revokeAll func(identity.ID) error
}

func (f *fakeSessionStore) Rotate(
	_ context.Context,
	rotation appauth.Rotation,
) error {
	if f.rotate == nil {
		return nil
	}

	return f.rotate(rotation)
}

func (f *fakeSessionStore) RevokeAll(
	_ context.Context,
	userID identity.ID,
) error {
	if f.revokeAll == nil {
		return nil
	}

	return f.revokeAll(userID)
}

type fakeUUIDGenerator struct {
	values []string
	index  int
}

func (f *fakeUUIDGenerator) GenerateString() (string, error) {
	if f.index >= len(f.values) {
		return "", errors.New("no UUID configured")
	}

	value := f.values[f.index]
	f.index++
	return value, nil
}
