package identity

import (
	"errors"
	"strings"
)

var errPlatformRoleInvalid = errors.New("platform role is invalid")

// PlatformRole represents an optional platform-wide administrative
// privilege. PlatformRoleNone is the ordinary, unprivileged identity state.
type PlatformRole string

const (
	PlatformRoleNone      PlatformRole = ""
	PlatformRoleAdmin     PlatformRole = "ADMIN"
	PlatformRoleViceAdmin PlatformRole = "VICE_ADMIN"
)

func ParsePlatformRole(raw string) (PlatformRole, error) {
	if raw == "" {
		return PlatformRoleNone, nil
	}

	role := PlatformRole(strings.TrimSpace(raw))
	if !role.IsValid() {
		return PlatformRoleNone, errPlatformRoleInvalid
	}

	return role, nil
}

func (r PlatformRole) IsAssigned() bool {
	return r.IsValid()
}

// IsValid reports whether the role is one of the supported assigned values.
func (r PlatformRole) IsValid() bool {
	switch r {
	case PlatformRoleAdmin, PlatformRoleViceAdmin:
		return true
	default:
		return false
	}
}

// IsValidOrEmpty also accepts the ordinary, unprivileged identity state.
func (r PlatformRole) IsValidOrEmpty() bool {
	return r == PlatformRoleNone || r.IsValid()
}

// CanCreatePlatformRole implements the deliberately narrow administrative
// hierarchy. ADMIN may create VICE_ADMIN; no API caller may create ADMIN.
func CanCreatePlatformRole(actor PlatformRole, target PlatformRole) bool {
	return actor == PlatformRoleAdmin && target == PlatformRoleViceAdmin
}
