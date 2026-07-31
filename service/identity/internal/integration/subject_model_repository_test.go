//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	appcreateidentity "github.com/DoMinhHHung/beexster/service/identity/internal/application/createidentity"
	appsignup "github.com/DoMinhHHung/beexster/service/identity/internal/application/signup"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/DoMinhHHung/beexster/service/identity/internal/platform/idgen"
	"github.com/DoMinhHHung/beexster/service/identity/internal/platform/passwordhash"
	"github.com/DoMinhHHung/beexster/service/identity/internal/platform/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSubjectRepositoriesPersistPlatformRoles(t *testing.T) {
	requireIntegrationTests(t)

	databaseURL := requireIntegrationDatabaseURL(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open PostgreSQL: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping PostgreSQL: %v", err)
	}

	ids := idgen.NewUUIDV7()
	hasher := passwordhash.New()
	now := time.Now().UTC().Truncate(time.Second)
	password := "Secure1!"
	identityIDs := make([]identity.ID, 0, 3)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		for _, identityID := range identityIDs {
			_, _ = pool.Exec(
				cleanupContext,
				`DELETE FROM identity.outbox_events WHERE aggregate_id = $1`,
				identityID.String(),
			)
			_, _ = pool.Exec(
				cleanupContext,
				`DELETE FROM identity.identities WHERE id = $1`,
				identityID.String(),
			)
		}
	})

	signupRepository, err := postgres.NewSignupRepository(pool)
	if err != nil {
		t.Fatalf("create signup repository: %v", err)
	}
	signupUseCase, err := appsignup.New(
		signupRepository,
		hasher,
		ids,
		ids,
		allowSignup{},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("create signup use case: %v", err)
	}

	emailSuffix, err := ids.GenerateString()
	if err != nil {
		t.Fatalf("generate email suffix: %v", err)
	}
	ordinaryEmail := "integration-signup+" + strings.ReplaceAll(emailSuffix, "-", "") + "@example.com"
	ordinary, err := signupUseCase.Execute(ctx, appsignup.Input{
		Email:     ordinaryEmail,
		Password:  password,
		Locale:    "en",
		IPAddress: netip.MustParseAddr("192.0.2.10"),
		RequestID: "integration-subject-signup",
	})
	if err != nil {
		t.Fatalf("public signup: %v", err)
	}
	identityIDs = append(identityIDs, ordinary.ID)

	var ordinaryRole sql.NullString
	if err := pool.QueryRow(
		ctx,
		`SELECT platform_role FROM identity.identities WHERE id = $1`,
		ordinary.ID.String(),
	).Scan(&ordinaryRole); err != nil {
		t.Fatalf("load public signup platform role: %v", err)
	}
	if ordinaryRole.Valid {
		t.Fatalf("public signup must store NULL platform role, got %q", ordinaryRole.String)
	}
	assertTransactionalCreationRecords(t, ctx, pool, ordinary.ID)

	actorID, err := ids.Generate()
	if err != nil {
		t.Fatalf("generate actor identity ID: %v", err)
	}
	identityIDs = append(identityIDs, actorID)
	actorPasswordHash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash actor password: %v", err)
	}
	actorEmail := "integration-admin+" + strings.ReplaceAll(actorID.String(), "-", "") + "@example.com"
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO identity.identities (
			id, email, password_hash, platform_role, status,
			email_verified_at, created_at, updated_at
		) VALUES ($1, $2, $3, 'ADMIN', 'active', $4, $4, $4)`,
		actorID.String(),
		actorEmail,
		actorPasswordHash,
		now,
	); err != nil {
		t.Fatalf("seed authoritative ADMIN: %v", err)
	}

	privilegedRepository, err := postgres.NewPrivilegedIdentityRepository(pool)
	if err != nil {
		t.Fatalf("create privileged repository: %v", err)
	}
	privilegedUseCase, err := appcreateidentity.New(
		privilegedRepository,
		hasher,
		ids,
		ids,
		func() time.Time { return now.Add(time.Minute) },
	)
	if err != nil {
		t.Fatalf("create privileged use case: %v", err)
	}
	viceEmail := "integration-vice+" + strings.ReplaceAll(actorID.String(), "-", "") + "@example.com"
	viceAdmin, err := privilegedUseCase.Execute(ctx, appcreateidentity.Input{
		ActorID:           actorID,
		ActorPlatformRole: identity.PlatformRoleAdmin,
		Email:             viceEmail,
		Password:          password,
		PlatformRole:      "VICE_ADMIN",
		Locale:            "en",
	})
	if err != nil {
		t.Fatalf("create VICE_ADMIN: %v", err)
	}
	identityIDs = append(identityIDs, viceAdmin.ID)

	var privilegedRole sql.NullString
	if err := pool.QueryRow(
		ctx,
		`SELECT platform_role FROM identity.identities WHERE id = $1`,
		viceAdmin.ID.String(),
	).Scan(&privilegedRole); err != nil {
		t.Fatalf("load privileged platform role: %v", err)
	}
	if !privilegedRole.Valid || privilegedRole.String != "VICE_ADMIN" {
		t.Fatalf("expected persisted VICE_ADMIN, got %+v", privilegedRole)
	}
	assertTransactionalCreationRecords(t, ctx, pool, viceAdmin.ID)

	rollbackTargetID, err := ids.Generate()
	if err != nil {
		t.Fatalf("generate rollback target ID: %v", err)
	}
	identityIDs = append(identityIDs, rollbackTargetID)
	rollbackVerificationID, err := ids.GenerateString()
	if err != nil {
		t.Fatalf("generate rollback verification ID: %v", err)
	}
	duplicateOutboxID, err := ids.GenerateString()
	if err != nil {
		t.Fatalf("generate duplicate outbox ID: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO identity.outbox_events (
			id, aggregate_id, event_type, payload, available_at, created_at
		) VALUES ($1, $2, 'identity.email_verification_requested', '{}'::jsonb, $3, $3)`,
		duplicateOutboxID,
		actorID.String(),
		now.Add(2*time.Minute),
	); err != nil {
		t.Fatalf("seed conflicting outbox event: %v", err)
	}
	rollbackEmail := "integration-rollback+" + strings.ReplaceAll(actorID.String(), "-", "") + "@example.com"
	err = privilegedRepository.Create(ctx, appcreateidentity.CreateParams{
		ActorID:                    actorID,
		IdentityID:                 rollbackTargetID,
		VerificationTokenID:        rollbackVerificationID,
		OutboxEventID:              duplicateOutboxID,
		Email:                      rollbackEmail,
		PasswordHash:               actorPasswordHash,
		PlatformRole:               identity.PlatformRoleViceAdmin,
		Status:                     identity.StatusActive,
		Locale:                     "en",
		CreatedAt:                  now.Add(2 * time.Minute),
		VerificationTokenExpiresAt: now.Add(time.Hour),
		OutboxEventType:            "identity.email_verification_requested",
	})
	if err == nil {
		t.Fatal("expected conflicting outbox insert to fail")
	}
	var (
		rolledBackIdentityCount int
		rolledBackTokenCount    int
	)
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.identities WHERE id = $1`,
		rollbackTargetID.String(),
	).Scan(&rolledBackIdentityCount); err != nil {
		t.Fatalf("check rolled-back identity: %v", err)
	}
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.email_verification_tokens WHERE id = $1`,
		rollbackVerificationID,
	).Scan(&rolledBackTokenCount); err != nil {
		t.Fatalf("check rolled-back verification token: %v", err)
	}
	if rolledBackIdentityCount != 0 || rolledBackTokenCount != 0 {
		t.Fatalf(
			"privileged transaction partially persisted: identities=%d tokens=%d",
			rolledBackIdentityCount,
			rolledBackTokenCount,
		)
	}

	compactActorID := strings.ReplaceAll(actorID.String(), "-", "")
	raceApplicationName := "identity-lock-" + compactActorID[:16]
	racePoolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal("parse concurrent-creation PostgreSQL configuration")
	}
	if racePoolConfig.ConnConfig.RuntimeParams == nil {
		racePoolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	racePoolConfig.ConnConfig.RuntimeParams["application_name"] = raceApplicationName
	racePoolConfig.MaxConns = 1
	racePool, err := pgxpool.NewWithConfig(ctx, racePoolConfig)
	if err != nil {
		t.Fatal("open concurrent-creation PostgreSQL pool")
	}
	defer racePool.Close()
	if err := racePool.Ping(ctx); err != nil {
		t.Fatal("ping concurrent-creation PostgreSQL pool")
	}
	raceRepository, err := postgres.NewPrivilegedIdentityRepository(racePool)
	if err != nil {
		t.Fatalf("create concurrent privileged repository: %v", err)
	}

	demotionTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin concurrent demotion: %v", err)
	}
	defer func() { _ = demotionTx.Rollback(context.Background()) }()
	if _, err := demotionTx.Exec(
		ctx,
		`UPDATE identity.identities
		 SET platform_role = 'VICE_ADMIN', updated_at = $2
		 WHERE id = $1`,
		actorID.String(),
		now.Add(3*time.Minute),
	); err != nil {
		t.Fatalf("hold concurrent actor demotion: %v", err)
	}

	raceTargetID, err := ids.Generate()
	if err != nil {
		t.Fatalf("generate race target ID: %v", err)
	}
	identityIDs = append(identityIDs, raceTargetID)
	raceVerificationID, err := ids.GenerateString()
	if err != nil {
		t.Fatalf("generate race verification ID: %v", err)
	}
	raceOutboxID, err := ids.GenerateString()
	if err != nil {
		t.Fatalf("generate race outbox ID: %v", err)
	}
	raceEmail := "integration-race+" + strings.ReplaceAll(actorID.String(), "-", "") + "@example.com"
	raceResult := make(chan error, 1)
	raceCreateContext, cancelRaceCreate := context.WithCancel(ctx)
	defer cancelRaceCreate()
	go func() {
		raceResult <- raceRepository.Create(
			raceCreateContext,
			appcreateidentity.CreateParams{
				ActorID:                    actorID,
				IdentityID:                 raceTargetID,
				VerificationTokenID:        raceVerificationID,
				OutboxEventID:              raceOutboxID,
				Email:                      raceEmail,
				PasswordHash:               actorPasswordHash,
				PlatformRole:               identity.PlatformRoleViceAdmin,
				Status:                     identity.StatusActive,
				Locale:                     "en",
				CreatedAt:                  now.Add(3 * time.Minute),
				VerificationTokenExpiresAt: now.Add(time.Hour),
				OutboxEventType:            "identity.email_verification_requested",
			},
		)
	}()

	lockObservationContext, cancelLockObservation := context.WithTimeout(
		ctx,
		5*time.Second,
	)
	defer cancelLockObservation()
	if err := waitForBlockedPrivilegedActorQuery(
		lockObservationContext,
		pool,
		raceApplicationName,
	); err != nil {
		cancelRaceCreate()
		t.Fatalf("observe privileged actor row lock: %v", err)
	}

	if err := demotionTx.Commit(ctx); err != nil {
		t.Fatalf("commit concurrent actor demotion: %v", err)
	}

	raceCompletionContext, cancelRaceCompletion := context.WithTimeout(
		ctx,
		5*time.Second,
	)
	defer cancelRaceCompletion()
	select {
	case raceErr := <-raceResult:
		if !errors.Is(raceErr, appcreateidentity.ErrActorForbidden) {
			t.Fatalf("expected race-safe actor rejection, got %v", raceErr)
		}
	case <-raceCompletionContext.Done():
		cancelRaceCreate()
		t.Fatalf(
			"privileged creation remained blocked after demotion committed: %v",
			raceCompletionContext.Err(),
		)
	}
	cancelRaceCreate()

	var raceTargetCount int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.identities WHERE id = $1`,
		raceTargetID.String(),
	).Scan(&raceTargetCount); err != nil {
		t.Fatalf("check concurrent-demotion target: %v", err)
	}
	if raceTargetCount != 0 {
		t.Fatal("concurrent demotion raced with privileged identity creation")
	}

	assertAuthoritativeActorRejected(
		t,
		ctx,
		pool,
		privilegedUseCase,
		actorID,
		password,
		"integration-stale-demoted+"+compactActorID+"@example.com",
	)

	if _, err := pool.Exec(
		ctx,
		`UPDATE identity.identities
		 SET platform_role = 'ADMIN', status = 'active',
		     email_verified_at = NULL, deleted_at = NULL, updated_at = $2
		 WHERE id = $1`,
		actorID.String(),
		now.Add(4*time.Minute),
	); err != nil {
		t.Fatalf("make authoritative actor unverified: %v", err)
	}
	assertAuthoritativeActorRejected(
		t,
		ctx,
		pool,
		privilegedUseCase,
		actorID,
		password,
		"integration-stale-unverified+"+compactActorID+"@example.com",
	)

	if _, err := pool.Exec(
		ctx,
		`UPDATE identity.identities
		 SET platform_role = 'ADMIN', status = 'inactive',
		     email_verified_at = $2, deleted_at = NULL, updated_at = $2
		 WHERE id = $1`,
		actorID.String(),
		now.Add(5*time.Minute),
	); err != nil {
		t.Fatalf("make authoritative actor inactive: %v", err)
	}
	assertAuthoritativeActorRejected(
		t,
		ctx,
		pool,
		privilegedUseCase,
		actorID,
		password,
		"integration-stale-inactive+"+compactActorID+"@example.com",
	)

	if _, err := pool.Exec(
		ctx,
		`UPDATE identity.identities
		 SET platform_role = 'ADMIN', status = 'inactive',
		     email_verified_at = $2, deleted_at = $2, updated_at = $2
		 WHERE id = $1`,
		actorID.String(),
		now.Add(6*time.Minute),
	); err != nil {
		t.Fatalf("make authoritative actor deleted: %v", err)
	}
	assertAuthoritativeActorRejected(
		t,
		ctx,
		pool,
		privilegedUseCase,
		actorID,
		password,
		"integration-stale-deleted+"+compactActorID+"@example.com",
	)
}

func waitForBlockedPrivilegedActorQuery(
	ctx context.Context,
	pool *pgxpool.Pool,
	applicationName string,
) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		var blocked bool
		err := pool.QueryRow(
			ctx,
			`SELECT EXISTS (
				SELECT 1
				FROM pg_stat_activity
				WHERE application_name = $1
				  AND wait_event_type = 'Lock'
				  AND cardinality(pg_blocking_pids(pid)) > 0
			)`,
			applicationName,
		).Scan(&blocked)
		if err != nil {
			return fmt.Errorf("inspect PostgreSQL lock wait: %w", err)
		}
		if blocked {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for PostgreSQL lock: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertAuthoritativeActorRejected(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	useCase *appcreateidentity.UseCase,
	actorID identity.ID,
	password string,
	targetEmail string,
) {
	t.Helper()

	_, err := useCase.Execute(ctx, appcreateidentity.Input{
		ActorID:           actorID,
		ActorPlatformRole: identity.PlatformRoleAdmin,
		Email:             targetEmail,
		Password:          password,
		PlatformRole:      "VICE_ADMIN",
		Locale:            "en",
	})
	assertDomainErrorCode(t, err, domain.ErrForbidden)

	var targetCount int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.identities WHERE email = $1`,
		targetEmail,
	).Scan(&targetCount); err != nil {
		t.Fatalf("check rejected privileged target: %v", err)
	}
	if targetCount != 0 {
		t.Fatalf("authoritatively rejected actor inserted target %q", targetEmail)
	}
}

func assertTransactionalCreationRecords(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	identityID identity.ID,
) {
	t.Helper()

	var (
		verificationTokenCount int
		outboxEventCount       int
	)
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.email_verification_tokens
		 WHERE identity_id = $1`,
		identityID.String(),
	).Scan(&verificationTokenCount); err != nil {
		t.Fatalf("count verification tokens: %v", err)
	}
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM identity.outbox_events
		 WHERE aggregate_id = $1
		   AND event_type = 'identity.email_verification_requested'`,
		identityID.String(),
	).Scan(&outboxEventCount); err != nil {
		t.Fatalf("count verification outbox events: %v", err)
	}
	if verificationTokenCount != 1 || outboxEventCount != 1 {
		t.Fatalf(
			"expected transactional token/outbox records, tokens=%d outbox=%d",
			verificationTokenCount,
			outboxEventCount,
		)
	}
}

func assertDomainErrorCode(t *testing.T, err error, expected domain.ErrorCode) {
	t.Helper()

	var domainError *domain.Error
	if !errors.As(err, &domainError) {
		t.Fatalf("expected domain error %q, got %v", expected, err)
	}
	if domainError.Code != expected {
		t.Fatalf("expected domain error %q, got %q", expected, domainError.Code)
	}
}

type allowSignup struct{}

func (allowSignup) AllowSignupIP(context.Context, string, netip.Addr) (bool, error) {
	return true, nil
}

func (allowSignup) AllowSignupEmail(context.Context, string, string) (bool, error) {
	return true, nil
}
