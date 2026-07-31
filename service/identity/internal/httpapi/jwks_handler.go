package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexster/service/identity/internal/platform/accesstoken"
)

const jwksCacheControl = "public, max-age=300"

type JWKSProvider interface {
	JWKS() accesstoken.JWKS
}

func jwksHandler(
	logger *slog.Logger,
	provider JWKSProvider,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if provider == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("JWKS provider is not initialized"),
				),
				logger,
			)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", jwksCacheControl)
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(provider.JWKS()); err != nil && logger != nil {
			logger.Warn("failed to encode JWKS response", slog.String("error", err.Error()))
		}
	}
}
