package sessionmanagement

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
	sessionManagementUserID = identity.ID(
		"0198f124-659f-7cbd-a441-dc7eea175073",
	)
	sessionManagementCurrentDevice = "0198f124-659f-7cbd-a441-dc7eea175074"
	sessionManagementOtherDevice   = "0198f124-659f-7cbd-a441-dc7eea175075"
)

var sessionManagementNow = time.Date(
	2026,
	time.July,
	30,
	13,
	0,
	0,
	0,
	time.UTC,
)

func TestServiceLogoutCurrentUsesAuthenticatedDevice(t *testing.T) {
	t.Parallel()

	var deletedDevice string
	service := newSessionService(t, &fakeStore{
		delete: func(
			_ context.Context,
			userID identity.ID,
			deviceID string,
		) error {
			if userID != sessionManagementUserID {
				t.Fatalf("unexpected user ID %q", userID)
			}

			deletedDevice = deviceID
			return nil
		},
	})

	if err := service.LogoutCurrent(
		context.Background(),
		validPrincipal(),
	); err != nil {
		t.Fatalf("logout current: %v", err)
	}

	if deletedDevice != sessionManagementCurrentDevice {
		t.Fatalf("unexpected deleted device %q", deletedDevice)
	}
}

func TestServiceLogoutAllRevokesUserSessions(t *testing.T) {
	t.Parallel()

	var revokedUserID identity.ID
	service := newSessionService(t, &fakeStore{
		revokeAll: func(
			_ context.Context,
			userID identity.ID,
		) error {
			revokedUserID = userID
			return nil
		},
	})

	if err := service.LogoutAll(
		context.Background(),
		validPrincipal(),
	); err != nil {
		t.Fatalf("logout all: %v", err)
	}

	if revokedUserID != sessionManagementUserID {
		t.Fatalf("unexpected revoked user ID %q", revokedUserID)
	}
}

func TestServiceListsSessionsWithoutTokenAndMarksCurrent(t *testing.T) {
	t.Parallel()

	service := newSessionService(t, &fakeStore{
		list: func(
			context.Context,
			identity.ID,
		) ([]appauth.Session, error) {
			return []appauth.Session{
				storedSession(
					sessionManagementOtherDevice,
					sessionManagementNow.Add(-time.Hour),
				),
				storedSession(
					sessionManagementCurrentDevice,
					sessionManagementNow,
				),
			}, nil
		},
	})

	sessions, err := service.List(
		context.Background(),
		validPrincipal(),
	)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}

	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	if sessions[0].DeviceID != sessionManagementCurrentDevice ||
		!sessions[0].Current {
		t.Fatalf("expected current session first, got %+v", sessions[0])
	}

	if sessions[1].Current {
		t.Fatal("other device must not be marked current")
	}
}

func TestServiceRejectsInvalidDeviceID(t *testing.T) {
	t.Parallel()

	service := newSessionService(t, &fakeStore{})

	err := service.Revoke(
		context.Background(),
		validPrincipal(),
		"not-a-device-id",
	)

	var domainError *domain.Error
	if !errors.As(err, &domainError) ||
		domainError.Code != domain.ErrInvalidInput {
		t.Fatalf("expected ERR_INVALID_INPUT, got %v", err)
	}
}

func newSessionService(t *testing.T, store Store) *Service {
	t.Helper()

	service, err := New(store)
	if err != nil {
		t.Fatalf("create session-management service: %v", err)
	}

	return service
}

func validPrincipal() appauth.Principal {
	return appauth.Principal{
		UserID:        sessionManagementUserID,
		DeviceID:      sessionManagementCurrentDevice,
		Role:          identity.RoleClient,
		EmailVerified: true,
	}
}

func storedSession(
	deviceID string,
	lastUsedAt time.Time,
) appauth.Session {
	return appauth.Session{
		Token:      "0198f124-659f-7cbd-a441-dc7eea175076",
		UserID:     sessionManagementUserID,
		DeviceID:   deviceID,
		UserAgent:  "test-agent",
		IPAddress:  netip.MustParseAddr("192.0.2.10"),
		CreatedAt:  sessionManagementNow.Add(-2 * time.Hour),
		ExpiresAt:  sessionManagementNow.Add(7 * 24 * time.Hour),
		LastUsedAt: lastUsedAt,
	}
}

type fakeStore struct {
	delete    func(context.Context, identity.ID, string) error
	revokeAll func(context.Context, identity.ID) error
	list      func(context.Context, identity.ID) ([]appauth.Session, error)
}

func (f *fakeStore) Delete(
	ctx context.Context,
	userID identity.ID,
	deviceID string,
) error {
	if f.delete == nil {
		return nil
	}

	return f.delete(ctx, userID, deviceID)
}

func (f *fakeStore) RevokeAll(
	ctx context.Context,
	userID identity.ID,
) error {
	if f.revokeAll == nil {
		return nil
	}

	return f.revokeAll(ctx, userID)
}

func (f *fakeStore) List(
	ctx context.Context,
	userID identity.ID,
) ([]appauth.Session, error) {
	if f.list == nil {
		return nil, nil
	}

	return f.list(ctx, userID)
}
