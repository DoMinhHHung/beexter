package postgres

import (
	"database/sql"
	"fmt"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func platformRoleFromNullString(
	raw sql.NullString,
) (identity.PlatformRole, error) {
	if !raw.Valid {
		return identity.PlatformRoleNone, nil
	}

	role := identity.PlatformRole(raw.String)
	if !role.IsValid() {
		return identity.PlatformRoleNone, fmt.Errorf(
			"%w: unknown platform role %q",
			ErrInvalidPersistedIdentity,
			raw.String,
		)
	}

	return role, nil
}
