package session

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	applogin "github.com/DoMinhHHung/beexter/service/identity/internal/application/login"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const (
	testUserID   = identity.ID("0198f124-659f-7cbd-a441-dc7eea175071")
	testDeviceID = "0198f124-659f-7cbd-a441-dc7eea175072"
	testTokenID  = "0198f124-659f-7cbd-a441-dc7eea175073"
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

func TestStoreSavesExactSessionContract(t *testing.T) {
	t.Parallel()

	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := NewStore(client, time.Second)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	err = store.Save(
		context.Background(),
		applogin.Session{
			Token:      testTokenID,
			UserID:     testUserID,
			DeviceID:   testDeviceID,
			UserAgent:  "test-agent",
			IPAddress:  mustParseAddress(t, "192.0.2.10"),
			CreatedAt:  sessionTestNow,
			ExpiresAt:  sessionTestNow.Add(refreshTokenTTL),
			LastUsedAt: sessionTestNow,
		},
	)
	if err != nil {
		t.Fatalf("save session: %v", err)
	}

	redisKey := key(testUserID, testDeviceID)
	rawValue, err := server.Get(redisKey)
	if err != nil {
		t.Fatalf("read stored session: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(rawValue), &payload); err != nil {
		t.Fatalf("decode session JSON: %v", err)
	}

	expectedKeys := []string{
		"token",
		"user_id",
		"device_id",
		"user_agent",
		"ip_address",
		"created_at",
		"expires_at",
		"last_used_at",
	}

	if len(payload) != len(expectedKeys) {
		t.Fatalf("unexpected JSON field count: %d", len(payload))
	}

	for _, expectedKey := range expectedKeys {
		if _, exists := payload[expectedKey]; !exists {
			t.Fatalf("missing JSON field %q", expectedKey)
		}
	}

	if ttl := server.TTL(redisKey); ttl != refreshTokenTTL {
		t.Fatalf("expected TTL %s, got %s", refreshTokenTTL, ttl)
	}
}

func TestStoreDeletesSession(t *testing.T) {
	t.Parallel()

	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := NewStore(client, time.Second)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	redisKey := key(testUserID, testDeviceID)
	server.Set(redisKey, `{}`)

	if err := store.Delete(
		context.Background(),
		testUserID,
		testDeviceID,
	); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	if server.Exists(redisKey) {
		t.Fatal("expected session key to be deleted")
	}
}

func mustParseAddress(t *testing.T, raw string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatalf("parse address: %v", err)
	}
	return address
}
