package postgres

import (
	"context"
	"errors"
	"fmt"

	appoutbox "github.com/DoMinhHHung/beexster/service/identity/internal/application/outbox"
	"github.com/jackc/pgx/v5"
)

const loadPasswordResetDeliverySQL = `
SELECT
    identity.email,
    token.expires_at,
    token.used_at,
    token.revoked_at
FROM identity.password_reset_tokens AS token
JOIN identity.identities AS identity
    ON identity.id = token.identity_id
WHERE identity.id = $1::uuid
  AND token.id = $2::uuid
  AND identity.status = 'active'
  AND identity.deleted_at IS NULL
`

func (r *OutboxRepository) LoadPasswordReset(
	ctx context.Context,
	identityID string,
	tokenID string,
) (appoutbox.PasswordResetDelivery, error) {
	if r == nil || r.database == nil {
		return appoutbox.PasswordResetDelivery{},
			ErrOutboxRepositoryNotInitialized
	}
	if ctx == nil {
		return appoutbox.PasswordResetDelivery{},
			ErrOutboxRepositoryContextRequired
	}

	var delivery appoutbox.PasswordResetDelivery
	err := r.database.QueryRow(
		ctx,
		loadPasswordResetDeliverySQL,
		identityID,
		tokenID,
	).Scan(
		&delivery.Email,
		&delivery.ExpiresAt,
		&delivery.UsedAt,
		&delivery.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return appoutbox.PasswordResetDelivery{},
			appoutbox.ErrDeliveryNotFound
	}
	if err != nil {
		return appoutbox.PasswordResetDelivery{}, fmt.Errorf(
			"load password-reset delivery: %w",
			err,
		)
	}

	return delivery, nil
}
