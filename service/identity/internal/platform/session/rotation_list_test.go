package session

import (
	"context"
	"net/netip"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
)

func TestStoreListAcceptsRotatedSession(t *testing.T) {
	t.Parallel()

	_, _, store := newTestStore(t)

	if err := store.Save(context.Background(), validSession()); err != nil {
		t.Fatalf("save session: %v", err)
	}

	rotationTime := sessionTestNow.Add(time.Hour)
	if err := store.Rotate(
		context.Background(),
		appauth.Rotation{
			UserID:             testUserID,
			DeviceID:           testDeviceID,
			PresentedTokenID:   testTokenID,
			ReplacementTokenID: nextTokenID,
			UserAgent:          "rotated-agent",
			IPAddress:          netip.MustParseAddr("198.51.100.10"),
			ExpiresAt:          rotationTime.Add(appauth.RefreshTokenTTL),
			LastUsedAt:         rotationTime,
		},
	); err != nil {
		t.Fatalf("rotate session: %v", err)
	}

	sessions, err := store.List(context.Background(), testUserID)
	if err != nil {
		t.Fatalf("list rotated session: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	current := sessions[0]
	if current.Token != nextTokenID {
		t.Fatalf("expected rotated token %q, got %q", nextTokenID, current.Token)
	}
	if !current.CreatedAt.Equal(sessionTestNow) {
		t.Fatalf("expected created_at %s, got %s", sessionTestNow, current.CreatedAt)
	}
	if !current.LastUsedAt.Equal(rotationTime) {
		t.Fatalf("expected last_used_at %s, got %s", rotationTime, current.LastUsedAt)
	}
	if !current.ExpiresAt.Equal(rotationTime.Add(appauth.RefreshTokenTTL)) {
		t.Fatalf("unexpected expires_at %s", current.ExpiresAt)
	}
}
