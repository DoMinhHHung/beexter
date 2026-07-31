package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func roleAuthorizationMiddleware(
	logger *slog.Logger,
	allowedRoles []identity.Role,
	next http.Handler,
) http.Handler {
	allowed := make(map[identity.Role]struct{}, len(allowedRoles))
	configurationValid := next != nil && len(allowedRoles) > 0

	for _, role := range allowedRoles {
		if !role.IsValid() {
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
					errors.New("role authorization middleware is not initialized"),
				),
				logger,
			)
			return
		}

		principal, ok := authenticatedPrincipalFromContext(r.Context())
		if !ok || principal.UserID.IsZero() || !principal.Role.IsValid() {
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

		if _, ok := allowed[principal.Role]; !ok {
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
