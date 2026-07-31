package session

import (
	"context"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func TestStoreRevokeCreatedAtOrBeforePreservesNewerSessions(
	t *testing.T,
) {
	t.Parallel()

	_, client, store := newTestStore(t)

	older := validSession()

	newer := validSession()
	newer.DeviceID = "0198f124-659f-7cbd-a441-dc7eea175077"
	newer.Token = "0198f124-659f-7cbd-a441-dc7eea175078"
	newer.CreatedAt = sessionTestNow.Add(10 * time.Second)
	newer.LastUsedAt = newer.CreatedAt
	newer.ExpiresAt = newer.CreatedAt.Add(appauth.RefreshTokenTTL)

	for _, current := range []appauth.Session{older, newer} {
		if err := store.Save(context.Background(), current); err != nil {
			t.Fatalf("save session: %v", err)
		}
	}

	cutoff := sessionTestNow.Add(5 * time.Second)
	if err := store.RevokeCreatedAtOrBefore(
		context.Background(),
		testUserID,
		cutoff,
	); err != nil {
		t.Fatalf("revoke sessions by cutoff: %v", err)
	}

	sessions, err := store.List(context.Background(), testUserID)
	if err != nil {
		t.Fatalf("list remaining sessions: %v", err)
	}

	if len(sessions) != 1 {
		t.Fatalf("expected 1 newer session, got %d", len(sessions))
	}

	if sessions[0].DeviceID != newer.DeviceID ||
		sessions[0].Token != newer.Token {
		t.Fatalf("unexpected remaining session: %+v", sessions[0])
	}

	stillIndexed, err := client.SIsMember(
		context.Background(),
		indexKey(testUserID),
		key(testUserID, older.DeviceID),
	).Result()
	if err != nil {
		t.Fatalf("check revoked index member: %v", err)
	}
	if stillIndexed {
		t.Fatal("revoked session must be removed from the index")
	}
}

func TestStoreRevokeCreatedAtOrBeforeDoesNotDeleteForeignSession(
	t *testing.T,
) {
	t.Parallel()

	_, client, store := newTestStore(t)

	foreignUserID := identity.ID(
		"0198f124-659f-7cbd-a441-dc7eea175079",
	)
	foreign := validSession()
	foreign.UserID = foreignUserID
	foreign.DeviceID = "0198f124-659f-7cbd-a441-dc7eea175080"
	foreign.Token = "0198f124-659f-7cbd-a441-dc7eea175081"

	if err := store.Save(context.Background(), foreign); err != nil {
		t.Fatalf("save foreign session: %v", err)
	}

	foreignKey := key(foreignUserID, foreign.DeviceID)
	if err := client.SAdd(
		context.Background(),
		indexKey(testUserID),
		foreignKey,
	).Err(); err != nil {
		t.Fatalf("add foreign index member: %v", err)
	}

	if err := store.RevokeCreatedAtOrBefore(
		context.Background(),
		testUserID,
		sessionTestNow.Add(time.Hour),
	); err != nil {
		t.Fatalf("revoke sessions by cutoff: %v", err)
	}

	exists, err := client.Exists(
		context.Background(),
		foreignKey,
	).Result()
	if err != nil {
		t.Fatalf("check foreign session: %v", err)
	}
	if exists != 1 {
		t.Fatal("foreign session must not be deleted")
	}

	stillIndexed, err := client.SIsMember(
		context.Background(),
		indexKey(testUserID),
		foreignKey,
	).Result()
	if err != nil {
		t.Fatalf("check foreign index member: %v", err)
	}
	if stillIndexed {
		t.Fatal("foreign session must be removed from the wrong index")
	}
}

func TestStoreRevokeCreatedAtOrBeforeRejectsZeroCutoff(
	t *testing.T,
) {
	t.Parallel()

	_, _, store := newTestStore(t)

	err := store.RevokeCreatedAtOrBefore(
		context.Background(),
		testUserID,
		time.Time{},
	)
	if err != ErrInvalidSession {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}
