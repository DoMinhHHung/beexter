package session

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
)

func TestRevocationFenceRejectsDelayedSessionSave(t *testing.T) {
	t.Parallel()

	_, _, store := newTestStore(t)
	cutoff := sessionTestNow.Add(time.Minute)
	if err := store.RevokeCreatedAtOrBefore(
		context.Background(),
		testUserID,
		cutoff,
	); err != nil {
		t.Fatalf("set revocation fence: %v", err)
	}

	delayed := validSession()
	err := store.Save(context.Background(), delayed)
	if !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("expected ErrSessionRevoked, got %v", err)
	}

	fresh := validSession()
	fresh.DeviceID = "0198f124-659f-7cbd-a441-dc7eea175080"
	fresh.Token = "0198f124-659f-7cbd-a441-dc7eea175081"
	fresh.CreatedAt = cutoff.Add(time.Second)
	fresh.LastUsedAt = fresh.CreatedAt
	fresh.ExpiresAt = fresh.LastUsedAt.Add(refreshTokenTTL)
	if err := store.Save(context.Background(), fresh); err != nil {
		t.Fatalf("save session created after cutoff: %v", err)
	}
}

func TestRevocationFenceMakesOldRefreshTokenUnusable(t *testing.T) {
	t.Parallel()

	_, _, store := newTestStore(t)
	current := validSession()
	if err := store.Save(context.Background(), current); err != nil {
		t.Fatalf("save current session: %v", err)
	}

	cutoff := current.CreatedAt.Add(time.Minute)
	if err := store.RevokeCreatedAtOrBefore(
		context.Background(),
		testUserID,
		cutoff,
	); err != nil {
		t.Fatalf("revoke old sessions: %v", err)
	}

	err := store.Rotate(
		context.Background(),
		appauth.Rotation{
			UserID:             testUserID,
			DeviceID:           testDeviceID,
			PresentedTokenID:   testTokenID,
			ReplacementTokenID: nextTokenID,
			UserAgent:          "test-agent",
			IPAddress:          netip.MustParseAddr("192.0.2.10"),
			ExpiresAt:          cutoff.Add(time.Minute).Add(refreshTokenTTL),
			LastUsedAt:         cutoff.Add(time.Minute),
		},
	)
	if !errors.Is(err, appauth.ErrRefreshTokenReuse) {
		t.Fatalf("expected refresh-token reuse error, got %v", err)
	}
}
