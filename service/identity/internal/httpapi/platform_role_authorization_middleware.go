package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

func platformRoleAuthorizationMiddleware(
	logger *slog.Logger,
	allowedRoles []identity.PlatformRole,
	next http.Handler,
) http.Handler {
	allowed := make(map[identity.PlatformRole]struct{}, len(allowedRoles))
	configurationValid := next != nil && len(allowedRoles) > 0

	for _, role := range allowedRoles {
		if !role.IsAssigned() || !role.IsValid() {
			configurationValid = false
			continue
		}

		allowed[role] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !configurationValid || len(allowed) == 0 {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("platform-role authorization middleware is not initialized"),
				),
				logger,
			)
			return
		}

		principal, ok := authenticatedPrincipalFromContext(r.Context())
		if !ok || principal.UserID.IsZero() ||
			!principal.PlatformRole.IsValidOrEmpty() {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("authenticated principal is missing for authorization"),
				),
				logger,
			)
			return
		}

		if _, ok := allowed[principal.PlatformRole]; !ok {
			writeApplicationError(
				w,
				r,
				domain.NewError(domain.ErrForbidden),
				logger,
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}
