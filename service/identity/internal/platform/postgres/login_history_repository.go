package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	apploginhistory "github.com/DoMinhHHung/beexster/service/identity/internal/application/loginhistory"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const listLoginHistorySQL = `
SELECT
    id::text,
    success,
    COALESCE(failure_code, ''),
    host(ip_address),
    user_agent,
    attempted_at
FROM identity.login_attempts
WHERE identity_id = $1::uuid
  AND ($2::timestamptz IS NULL OR attempted_at < $2)
ORDER BY attempted_at DESC, id DESC
LIMIT $3
`

var (
	ErrLoginHistoryRepositoryNotInitialized = errors.New(
		"login-history repository is not initialized",
	)
	ErrLoginHistoryRepositoryContextRequired = errors.New(
		"login-history repository context is required",
	)
)

type loginHistoryDatabase interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

type LoginHistoryRepository struct {
	database loginHistoryDatabase
}

func NewLoginHistoryRepository(
	database loginHistoryDatabase,
) (*LoginHistoryRepository, error) {
	if database == nil {
		return nil, ErrLoginHistoryRepositoryNotInitialized
	}
	return &LoginHistoryRepository{database: database}, nil
}

func (r *LoginHistoryRepository) List(
	ctx context.Context,
	identityID identity.ID,
	limit int,
	before *time.Time,
) ([]apploginhistory.Attempt, error) {
	if r == nil || r.database == nil {
		return nil, ErrLoginHistoryRepositoryNotInitialized
	}
	if ctx == nil {
		return nil, ErrLoginHistoryRepositoryContextRequired
	}

	rows, err := r.database.Query(
		ctx,
		listLoginHistorySQL,
		identityID.String(),
		before,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query login history: %w", err)
	}
	defer rows.Close()

	attempts := make([]apploginhistory.Attempt, 0, limit)
	for rows.Next() {
		var (
			attempt      apploginhistory.Attempt
			rawIPAddress string
		)
		if err := rows.Scan(
			&attempt.ID,
			&attempt.Success,
			&attempt.FailureCode,
			&rawIPAddress,
			&attempt.UserAgent,
			&attempt.AttemptedAt,
		); err != nil {
			return nil, fmt.Errorf("scan login history: %w", err)
		}

		parsedID, err := uuid.Parse(attempt.ID)
		if err != nil || parsedID.Version() != 7 ||
			parsedID.Variant() != uuid.RFC4122 || parsedID.String() != attempt.ID {
			return nil, fmt.Errorf(
				"%w: invalid login-attempt ID",
				ErrInvalidPersistedIdentity,
			)
		}
		attempt.IPAddress, err = netip.ParseAddr(rawIPAddress)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: invalid login-attempt IP address: %v",
				ErrInvalidPersistedIdentity,
				err,
			)
		}
		attempt.IPAddress = attempt.IPAddress.Unmap()
		attempt.AttemptedAt = attempt.AttemptedAt.UTC()
		attempts = append(attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate login history: %w", err)
	}
	return attempts, nil
}

var _ apploginhistory.Repository = (*LoginHistoryRepository)(nil)
