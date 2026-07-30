package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const readinessTimeout = 2 * time.Second

type statusResponse struct {
	Status string `json:"status"`
}

func NewRouter(
	logger *slog.Logger,
	database *pgxpool.Pool,
	cache *redis.Client,
	signupExecutor SignupExecutor,
	verifyEmailExecutor VerifyEmailExecutor,
	resendVerificationExecutor ResendVerificationExecutor,
) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(
		"GET /health",
		healthHandler(logger),
	)

	mux.HandleFunc(
		"GET /ready",
		readinessHandler(
			logger,
			database,
			cache,
		),
	)

	mux.HandleFunc(
		"POST /v1/auth/signup",
		signupHandler(
			logger,
			signupExecutor,
		),
	)

	mux.HandleFunc(
		"POST /v1/auth/verify-email",
		verifyEmailHandler(
			logger,
			verifyEmailExecutor,
		),
	)

	mux.HandleFunc(
		"POST /v1/auth/resend-verification",
		resendVerificationHandler(
			logger,
			resendVerificationExecutor,
		),
	)

	return applyMiddleware(logger, mux)
}

func healthHandler(
	logger *slog.Logger,
) http.HandlerFunc {
	return func(
		w http.ResponseWriter,
		_ *http.Request,
	) {
		writeJSON(
			w,
			http.StatusOK,
			statusResponse{
				Status: "ok",
			},
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

		if err := database.Ping(ctx); err != nil {
			logger.Warn(
				"readiness check failed",
				slog.String(
					"dependency",
					"postgresql",
				),
				slog.String(
					"error",
					err.Error(),
				),
			)

			writeError(
				w,
				http.StatusServiceUnavailable,
				"ERR_INTERNAL",
				"service is not ready",
				requestIDFromContext(
					r.Context(),
				),
				logger,
			)

			return
		}

		if err := cache.Ping(ctx).Err(); err != nil {
			logger.Warn(
				"readiness check failed",
				slog.String(
					"dependency",
					"redis",
				),
				slog.String(
					"error",
					err.Error(),
				),
			)

			writeError(
				w,
				http.StatusServiceUnavailable,
				"ERR_INTERNAL",
				"service is not ready",
				requestIDFromContext(
					r.Context(),
				),
				logger,
			)

			return
		}

		writeJSON(
			w,
			http.StatusOK,
			statusResponse{
				Status: "ready",
			},
			logger,
		)
	}
}
