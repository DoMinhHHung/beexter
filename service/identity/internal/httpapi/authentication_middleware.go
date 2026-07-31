package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	authenticateapp "github.com/DoMinhHHung/beexster/service/identity/internal/application/authenticate"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
)

type authenticatedPrincipalContextKey struct{}

type Authenticator interface {
	Execute(
		ctx context.Context,
		input authenticateapp.Input,
	) (appauth.Principal, error)
}

func authenticationMiddleware(
	logger *slog.Logger,
	authenticator Authenticator,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authenticator == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("authenticator is not initialized"),
				),
				logger,
			)
			return
		}

		rawToken, err := bearerToken(r.Header.Values("Authorization"))
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeApplicationError(
				w,
				r,
				domain.WrapError(domain.ErrTokenInvalid, err),
				logger,
			)
			return
		}

		principal, err := authenticator.Execute(
			r.Context(),
			authenticateapp.Input{AccessToken: rawToken},
		)
		if err != nil {
			var domainError *domain.Error
			if errors.As(err, &domainError) &&
				(domainError.Code == domain.ErrTokenInvalid ||
					domainError.Code == domain.ErrTokenExpired ||
					domainError.Code == domain.ErrInvalidCredentials) {
				w.Header().Set("WWW-Authenticate", "Bearer")
			}

			writeApplicationError(w, r, err, logger)
			return
		}

		ctx := context.WithValue(
			r.Context(),
			authenticatedPrincipalContextKey{},
			principal,
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(values []string) (string, error) {
	if len(values) != 1 {
		return "", errors.New(
			"exactly one Authorization header is required",
		)
	}

	parts := strings.Fields(values[0])
	if len(parts) != 2 ||
		!strings.EqualFold(parts[0], "Bearer") ||
		parts[1] == "" {
		return "", errors.New("Authorization header must use Bearer scheme")
	}

	return parts[1], nil
}

func authenticatedPrincipalFromContext(
	ctx context.Context,
) (appauth.Principal, bool) {
	principal, ok := ctx.Value(
		authenticatedPrincipalContextKey{},
	).(appauth.Principal)

	return principal, ok
}
