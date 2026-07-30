package session

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const (
	testUserID = identity.ID(
		"0198f124-659f-7cbd-a441-dc7eea175073",
	)
	testDeviceID = "0198f124-659f-7cbd-a441-dc7eea175074"
	testTokenID  = "0198f124-659f-7cbd-a441-dc7eea175075"
	nextTokenID  = "0198f124-659f-7cbd-a441-dc7eea175076"
)

var sessionTestNow = time.Date(
	2026,
	time.July,
	30,
	12,
	0,
	0,
	0,
	time.UTC,
)

func TestStoreSaveAndRotate(t *testing.T) {
	t.Parallel()

	server, client, store := newTestStore(t)

	original := validSession()
	if err := store.Save(context.Background(), original); err != nil {
		t.Fatalf("save session: %v", err)
	}

	rotationTime := sessionTestNow.Add(time.Hour)
	err := store.Rotate(
		context.Background(),
		appauth.Rotation{
			UserID:             testUserID,
			DeviceID:           testDeviceID,
			PresentedTokenID:   testTokenID,
			ReplacementTokenID: nextTokenID,
			UserAgent:          "updated-agent",
			IPAddress:          netip.MustParseAddr("198.51.100.10"),
			ExpiresAt: rotationTime.Add(
				appauth.RefreshTokenTTL,
			),
			LastUsedAt: rotationTime,
		},
	)
	if err != nil {
		t.Fatalf("rotate session: %v", err)
	}

	rawPayload, err := client.Get(
		context.Background(),
		key(testUserID, testDeviceID),
	).Bytes()
	if err != nil {
		t.Fatalf("get rotated session: %v", err)
	}

	var payload redisPayload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		t.Fatalf("decode rotated session: %v", err)
	}

	if payload.Token != nextTokenID ||
		payload.UserAgent != "updated-agent" ||
		payload.IPAddress != "198.51.100.10" {
		t.Fatalf("unexpected rotated payload: %+v", payload)
	}

	if payload.CreatedAt != sessionTestNow.Format(time.RFC3339) {
		t.Fatalf("rotation must preserve created_at, got %q", payload.CreatedAt)
	}

	ttl := server.TTL(key(testUserID, testDeviceID))
	if ttl != refreshTokenTTL {
		t.Fatalf("expected TTL %s, got %s", refreshTokenTTL, ttl)
	}
}

func TestStoreDetectsReuseAndRevokesAllSessions(t *testing.T) {
	t.Parallel()

	_, client, store := newTestStore(t)

	first := validSession()
	second := validSession()
	second.DeviceID = "0198f124-659f-7cbd-a441-dc7eea175077"
	second.Token = "0198f124-659f-7cbd-a441-dc7eea175078"

	for _, current := range []appauth.Session{first, second} {
		if err := store.Save(context.Background(), current); err != nil {
			t.Fatalf("save session: %v", err)
		}
	}

	err := store.Rotate(
		context.Background(),
		appauth.Rotation{
			UserID:             testUserID,
			DeviceID:           testDeviceID,
			PresentedTokenID:   "0198f124-659f-7cbd-a441-dc7eea175079",
			ReplacementTokenID: nextTokenID,
			UserAgent:          "test-agent",
			IPAddress:          netip.MustParseAddr("192.0.2.10"),
			ExpiresAt:          sessionTestNow.Add(appauth.RefreshTokenTTL),
			LastUsedAt:         sessionTestNow,
		},
	)
	if !errors.Is(err, appauth.ErrRefreshTokenReuse) {
		t.Fatalf("expected reuse error, got %v", err)
	}

	for _, deviceID := range []string{first.DeviceID, second.DeviceID} {
		exists, err := client.Exists(
			context.Background(),
			key(testUserID, deviceID),
		).Result()
		if err != nil {
			t.Fatalf("check session existence: %v", err)
		}

		if exists != 0 {
			t.Fatalf("expected device %s to be revoked", deviceID)
		}
	}
}

func TestStoreMissingSessionIsReuse(t *testing.T) {
	t.Parallel()

	_, _, store := newTestStore(t)

	err := store.Rotate(
		context.Background(),
		appauth.Rotation{
			UserID:             testUserID,
			DeviceID:           testDeviceID,
			PresentedTokenID:   testTokenID,
			ReplacementTokenID: nextTokenID,
			UserAgent:          "test-agent",
			IPAddress:          netip.MustParseAddr("192.0.2.10"),
			ExpiresAt:          sessionTestNow.Add(appauth.RefreshTokenTTL),
			LastUsedAt:         sessionTestNow,
		},
	)
	if !errors.Is(err, appauth.ErrRefreshTokenReuse) {
		t.Fatalf("expected reuse error, got %v", err)
	}
}

func TestStoreRevokeAll(t *testing.T) {
	t.Parallel()

	_, client, store := newTestStore(t)

	if err := store.Save(context.Background(), validSession()); err != nil {
		t.Fatalf("save session: %v", err)
	}

	if err := store.RevokeAll(context.Background(), testUserID); err != nil {
		t.Fatalf("revoke all: %v", err)
	}

	exists, err := client.Exists(
		context.Background(),
		key(testUserID, testDeviceID),
	).Result()
	if err != nil {
		t.Fatalf("check session: %v", err)
	}

	if exists != 0 {
		t.Fatal("expected session to be revoked")
	}
}

func validSession() appauth.Session {
	return appauth.Session{
		Token:      testTokenID,
		UserID:     testUserID,
		DeviceID:   testDeviceID,
		UserAgent:  "test-agent",
		IPAddress:  netip.MustParseAddr("192.0.2.10"),
		CreatedAt:  sessionTestNow,
		ExpiresAt:  sessionTestNow.Add(appauth.RefreshTokenTTL),
		LastUsedAt: sessionTestNow,
	}
}

func newTestStore(
	t *testing.T,
) (*miniredis.Miniredis, *redis.Client, *Store) {
	t.Helper()

	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})

	store, err := NewStore(client, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	return server, client, store
}
