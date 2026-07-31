package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const readinessTimeout = 2 * time.Second

type statusResponse struct {
	Status string `json:"status"`
}

type RouterDependencies struct {
	Signup                   SignupExecutor
	Login                    LoginExecutor
	Refresh                  RefreshExecutor
	VerifyEmail              VerifyEmailExecutor
	ResendVerification       ResendVerificationExecutor
	ForgotPassword           ForgotPasswordExecutor
	ResetPassword            ResetPasswordExecutor
	ChangePassword           ChangePasswordExecutor
	Me                       GetMeExecutor
	CreatePrivilegedIdentity CreatePrivilegedIdentityExecutor
	Reactivation             ReactivationExecutor
	DeleteAccount            DeleteAccountExecutor
	LoginHistory             LoginHistoryExecutor
	Authenticator            Authenticator
	Sessions                 SessionManager
	JWKS                     JWKSProvider
	TrustedProxyPrefixes     []netip.Prefix
}

func NewRouter(
	logger *slog.Logger,
	database *pgxpool.Pool,
	cache *redis.Client,
	dependencies RouterDependencies,
) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(
		"GET /health",
		healthHandler(logger),
	)

	mux.HandleFunc(
		"GET /ready",
		readinessHandler(logger, database, cache),
	)

	mux.HandleFunc("GET /openapi.yaml", openAPIHandler(logger))
	mux.HandleFunc("GET /docs", swaggerUIHandler(logger))
	mux.HandleFunc(
		"GET /.well-known/jwks.json",
		jwksHandler(logger, dependencies.JWKS),
	)

	mux.HandleFunc(
		"POST /v1/auth/signup",
		signupHandler(logger, dependencies.Signup),
	)

	mux.HandleFunc(
		"POST /v1/auth/login",
		loginHandler(logger, dependencies.Login),
	)

	mux.HandleFunc(
		"POST /v1/auth/refresh",
		refreshHandler(logger, dependencies.Refresh),
	)

	mux.HandleFunc(
		"POST /v1/auth/verify-email",
		verifyEmailHandler(logger, dependencies.VerifyEmail),
	)

	mux.HandleFunc(
		"POST /v1/auth/resend-verification",
		resendVerificationHandler(
			logger,
			dependencies.ResendVerification,
		),
	)

	passwordResetRequestHandler := forgotPasswordHandler(
		logger,
		dependencies.ForgotPassword,
	)
	mux.HandleFunc(
		"POST /v1/auth/forgot-password",
		passwordResetRequestHandler,
	)
	mux.HandleFunc(
		"POST /v1/auth/resend-password-reset",
		passwordResetRequestHandler,
	)

	mux.HandleFunc(
		"POST /v1/auth/request-reactivation",
		requestReactivationHandler(logger, dependencies.Reactivation),
	)

	mux.HandleFunc(
		"POST /v1/auth/reset-password",
		resetPasswordHandler(
			logger,
			dependencies.ResetPassword,
		),
	)

	protected := func(handler http.Handler) http.Handler {
		return authenticationMiddleware(
			logger,
			dependencies.Authenticator,
			handler,
		)
	}

	mux.Handle(
		"PUT /v1/auth/change-password",
		protected(changePasswordHandler(logger, dependencies.ChangePassword)),
	)

	mux.Handle(
		"POST /v1/auth/logout",
		protected(logoutCurrentHandler(logger, dependencies.Sessions)),
	)

	mux.Handle(
		"POST /v1/auth/logout-all",
		protected(logoutAllHandler(logger, dependencies.Sessions)),
	)

	mux.Handle(
		"GET /v1/me",
		protected(meHandler(logger, dependencies.Me)),
	)

	mux.Handle(
		"DELETE /v1/me",
		protected(deleteAccountHandler(logger, dependencies.DeleteAccount)),
	)

	mux.Handle(
		"GET /v1/me/login-history",
		protected(loginHistoryHandler(logger, dependencies.LoginHistory)),
	)

	mux.Handle(
		"GET /v1/me/sessions",
		protected(listSessionsHandler(logger, dependencies.Sessions)),
	)

	mux.Handle(
		"DELETE /v1/me/sessions/{device_id}",
		protected(revokeSessionHandler(logger, dependencies.Sessions)),
	)

	privilegedIdentityCreators := []identity.PlatformRole{
		identity.PlatformRoleAdmin,
	}
	mux.Handle(
		"POST /v1/admin/identities",
		protected(
			platformRoleAuthorizationMiddleware(
				logger,
				privilegedIdentityCreators,
				createPrivilegedIdentityHandler(
					logger,
					dependencies.CreatePrivilegedIdentity,
				),
			),
		),
	)

	return trustedProxyMiddleware(
		dependencies.TrustedProxyPrefixes,
		applyMiddleware(logger, mux),
	)
}

func healthHandler(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(
			w,
			http.StatusOK,
			statusResponse{Status: "ok"},
			logger,
		)
	}
}

func readinessHandler(
	logger *slog.Logger,
	database *pgxpool.Pool,
	cache *redis.Client,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(
			r.Context(),
			readinessTimeout,
		)
		defer cancel()

		if database == nil {
			writeError(
				w,
				http.StatusServiceUnavailable,
				"ERR_INTERNAL",
				"service is not ready",
				requestIDFromContext(r.Context()),
				logger,
			)
			return
		}

		if err := database.Ping(ctx); err != nil {
			logger.Warn(
				"readiness check failed",
				slog.String("dependency", "postgresql"),
				slog.String("error", err.Error()),
			)

			writeError(
				w,
				http.StatusServiceUnavailable,
				"ERR_INTERNAL",
				"service is not ready",
				requestIDFromContext(r.Context()),
				logger,
			)
			return
		}

		if cache == nil {
			writeError(
				w,
				http.StatusServiceUnavailable,
				"ERR_INTERNAL",
				"service is not ready",
				requestIDFromContext(r.Context()),
				logger,
			)
			return
		}

		if err := cache.Ping(ctx).Err(); err != nil {
			logger.Warn(
				"readiness check failed",
				slog.String("dependency", "redis"),
				slog.String("error", err.Error()),
			)

			writeError(
				w,
				http.StatusServiceUnavailable,
				"ERR_INTERNAL",
				"service is not ready",
				requestIDFromContext(r.Context()),
				logger,
			)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			statusResponse{Status: "ready"},
			logger,
		)
	}
}
