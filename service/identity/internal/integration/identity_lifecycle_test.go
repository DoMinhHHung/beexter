//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	appcleanup "github.com/DoMinhHHung/beexter/service/identity/internal/application/cleanup"
	appdeleteaccount "github.com/DoMinhHHung/beexter/service/identity/internal/application/deleteaccount"
	appreactivation "github.com/DoMinhHHung/beexter/service/identity/internal/application/requestreactivation"
	appverifyemail "github.com/DoMinhHHung/beexter/service/identity/internal/application/verifyemail"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/idgen"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/passwordhash"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/postgres"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/session"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func TestSoftDeleteReactivationAndCleanup(t *testing.T) {
	if strings.TrimSpace(os.Getenv("IDENTITY_INTEGRATION_TEST")) != "1" {
		t.Skip("set IDENTITY_INTEGRATION_TEST=1 and use isolated PostgreSQL/Redis instances")
	}

	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_DIRECT_URL"))
	if databaseURL == "" {
		databaseURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	}
	redisAddress := strings.TrimSpace(os.Getenv("REDIS_ADDR"))
	if databaseURL == "" || redisAddress == "" {
		t.Skip("DATABASE_DIRECT_URL or DATABASE_URL and REDIS_ADDR are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping PostgreSQL: %v", err)
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddress,
		Username: os.Getenv("REDIS_USERNAME"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       integrationRedisDB(),
	})
	defer func() { _ = redisClient.Close() }()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping Redis: %v", err)
	}

	ids := idgen.NewUUIDV7()
	identityID, err := ids.Generate()
	if err != nil {
		t.Fatalf("generate identity ID: %v", err)
	}
	email := "integration+" + strings.ReplaceAll(identityID.String(), "-", "") + "@example.com"
	password := "Secure1!"
	hasher := passwordhash.New()
	passwordHash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)

	_, err = pool.Exec(
		ctx,
		`INSERT INTO identity.identities (
			id, email, password_hash, role, status, email_verified_at,
			soft_delete_count, created_at, updated_at
		) VALUES ($1, $2, $3, 'JOB_SEEKER', 'active', $4, 0, $4, $4)`,
		identityID.String(),
		email,
		passwordHash,
		now,
	)
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = pool.Exec(cleanupContext, `DELETE FROM identity.outbox_events WHERE aggregate_id = $1`, identityID.String())
		_, _ = pool.Exec(cleanupContext, `DELETE FROM identity.identities WHERE id = $1`, identityID.String())
		_ = redisClient.Del(
			cleanupContext,
			"refresh_token_index:"+identityID.String(),
			"refresh_token_revoked_before:"+identityID.String(),
		).Err()
	})

	sessionStore, err := session.NewStore(redisClient, time.Second)
	if err != nil {
		t.Fatalf("create session store: %v", err)
	}
	deviceID, _ := ids.GenerateString()
	refreshID, _ := ids.GenerateString()
	if err := sessionStore.Save(ctx, appauth.Session{
		Token:      refreshID,
		UserID:     identityID,
		DeviceID:   deviceID,
		UserAgent:  "integration-test",
		IPAddress:  netip.MustParseAddr("192.0.2.10"),
		CreatedAt:  now,
		ExpiresAt:  now.Add(appauth.RefreshTokenTTL),
		LastUsedAt: now,
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	deleteRepository, err := postgres.NewDeleteAccountRepository(pool)
	if err != nil {
		t.Fatalf("create delete repository: %v", err)
	}
	deleteUseCase, err := appdeleteaccount.New(
		deleteRepository,
		hasher,
		allowDeleteLifecycle{},
		sessionStore,
		func() time.Time { return now.Add(time.Minute) },
	)
	if err != nil {
		t.Fatalf("create delete use case: %v", err)
	}
	deleteOutput, err := deleteUseCase.Execute(ctx, appdeleteaccount.Input{
		UserID:          identityID,
		CurrentPassword: password,
		IPAddress:       netip.MustParseAddr("192.0.2.10"),
		RequestID:       "integration-delete",
	})
	if err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if deleteOutput.HardDeleted || deleteOutput.SoftDeleteCount != 1 {
		t.Fatalf("unexpected delete output: %+v", deleteOutput)
	}
	if sessions, err := sessionStore.List(ctx, identityID); err != nil || len(sessions) != 0 {
		t.Fatalf("sessions must be revoked, sessions=%d err=%v", len(sessions), err)
	}

	dummyHash, err := hasher.Hash("DummyIntegration1!")
	if err != nil {
		t.Fatalf("hash dummy password: %v", err)
	}
	reactivationRepository, err := postgres.NewReactivationRepository(pool)
	if err != nil {
		t.Fatalf("create reactivation repository: %v", err)
	}
	reactivationUseCase, err := appreactivation.New(
		reactivationRepository,
		hasher,
		ids,
		allowReactivation{},
		dummyHash,
		func() time.Time { return now.Add(2 * time.Minute) },
	)
	if err != nil {
		t.Fatalf("create reactivation use case: %v", err)
	}
	if _, err := reactivationUseCase.Execute(ctx, appreactivation.Input{
		Email:     email,
		Password:  password,
		Locale:    "vi-VN",
		IPAddress: netip.MustParseAddr("192.0.2.10"),
		RequestID: "integration-reactivation",
	}); err != nil {
		t.Fatalf("request reactivation: %v", err)
	}

	var verificationToken string
	if err := pool.QueryRow(
		ctx,
		`SELECT id::text FROM identity.email_verification_tokens
		 WHERE identity_id = $1 AND used_at IS NULL AND revoked_at IS NULL`,
		identityID.String(),
	).Scan(&verificationToken); err != nil {
		t.Fatalf("load reactivation token: %v", err)
	}
	verifyRepository, err := postgres.NewVerifyEmailRepository(pool)
	if err != nil {
		t.Fatalf("create verify repository: %v", err)
	}
	verifyUseCase, err := appverifyemail.New(
		verifyRepository,
		func() time.Time { return now.Add(3 * time.Minute) },
	)
	if err != nil {
		t.Fatalf("create verify use case: %v", err)
	}
	verified, err := verifyUseCase.Execute(ctx, appverifyemail.Input{Token: verificationToken})
	if err != nil {
		t.Fatalf("verify reactivation: %v", err)
	}
	if !verified.Reactivated || !verified.EmailVerified {
		t.Fatalf("unexpected verification output: %+v", verified)
	}

	oldAttemptID, _ := ids.GenerateString()
	oldAttemptedAt := now.Add(-31 * 24 * time.Hour)
	_, err = pool.Exec(
		ctx,
		`INSERT INTO identity.login_attempts (
			id, identity_id, email, success, failure_code, ip_address,
			user_agent, request_id, attempted_at
		) VALUES ($1, $2, $3, false, 'ERR_INVALID_CREDENTIALS',
			'192.0.2.10', 'integration-test', 'old-attempt', $4)`,
		oldAttemptID,
		identityID.String(),
		email,
		oldAttemptedAt,
	)
	if err != nil {
		t.Fatalf("seed old login attempt: %v", err)
	}

	cleanupRepository, err := postgres.NewCleanupRepository(pool)
	if err != nil {
		t.Fatalf("create cleanup repository: %v", err)
	}
	stats, err := cleanupRepository.Cleanup(ctx, appcleanup.Params{
		LoginAttemptsBefore:   now.Add(-30 * 24 * time.Hour),
		TokensExpiredBefore:   now.Add(-24 * time.Hour),
		OutboxProcessedBefore: now.Add(-7 * 24 * time.Hour),
		BatchSize:             100,
	})
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if stats.LoginAttemptsDeleted < 1 {
		t.Fatalf("expected old login attempt cleanup, stats=%+v", stats)
	}
}

func integrationRedisDB() int {
	var database int
	_, _ = fmt.Sscanf(strings.TrimSpace(os.Getenv("REDIS_DB")), "%d", &database)
	return database
}

type allowDeleteLifecycle struct{}

func (allowDeleteLifecycle) AllowDeleteAccountIP(context.Context, string, netip.Addr) (bool, error) {
	return true, nil
}
func (allowDeleteLifecycle) AllowDeleteAccountIdentity(context.Context, string, identity.ID) (bool, error) {
	return true, nil
}

type allowReactivation struct{}

func (allowReactivation) AllowReactivationIP(context.Context, string, netip.Addr) (bool, error) {
	return true, nil
}
func (allowReactivation) AllowReactivationEmail(context.Context, string, string) (bool, error) {
	return true, nil
}
