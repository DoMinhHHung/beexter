package identity

import "strings"

func ParseRole(rawRole string) (Role, error) {
	role := Role(strings.ToUpper(strings.TrimSpace(rawRole)))
	if !role.IsValid() {
		return "", errRoleInvalid
	}

	return role, nil
}

// CanCreateRole implements the intentionally small role-creation hierarchy:
//
//   - ADMIN may create VICE_ADMIN and AGENCY identities.
//   - VICE_ADMIN may create AGENCY identities.
//   - No API caller may create ADMIN, CLIENT, or JOB_SEEKER through the
//     privileged identity endpoint.
func CanCreateRole(actor Role, target Role) bool {
	switch actor {
	case RoleAdmin:
		return target == RoleViceAdmin || target == RoleAgency

	case RoleViceAdmin:
		return target == RoleAgency

	default:
		return false
	}
}
