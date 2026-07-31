package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	appcreateidentity "github.com/DoMinhHHung/beexter/service/identity/internal/application/createidentity"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

type CreatePrivilegedIdentityExecutor interface {
	Execute(
		ctx context.Context,
		input appcreateidentity.Input,
	) (appcreateidentity.Output, error)
}

type createPrivilegedIdentityRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type createPrivilegedIdentityResponse struct {
	Data createPrivilegedIdentityResponseData `json:"data"`
}

type createPrivilegedIdentityResponseData struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Role          string `json:"role"`
	EmailVerified bool   `json:"email_verified"`
}

func createPrivilegedIdentityHandler(
	logger *slog.Logger,
	executor CreatePrivilegedIdentityExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("create privileged identity executor is not initialized"),
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
					errors.New("authenticated principal is missing"),
				),
				logger,
			)
			return
		}

		var request createPrivilegedIdentityRequest
		if err := decodeJSONBody(w, r, &request); err != nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(domain.ErrInvalidInput, err),
				logger,
			)
			return
		}

		requestID := requestIDFromContext(r.Context())
		if requestID == "" {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("request ID is missing from context"),
				),
				logger,
			)
			return
		}

		output, err := executor.Execute(
			r.Context(),
			appcreateidentity.Input{
				ActorID:   principal.UserID,
				ActorRole: principal.Role,
				Email:     request.Email,
				Password:  request.Password,
				Role:      request.Role,
				Locale:    parseAcceptLanguage(r.Header.Get("Accept-Language")),
			},
		)
		if err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		logger.Info(
			"privileged identity created",
			slog.String("request_id", requestID),
			slog.String("actor_identity_id", principal.UserID.String()),
			slog.String("actor_role", string(principal.Role)),
			slog.String("created_identity_id", output.ID.String()),
			slog.String("created_role", string(output.Role)),
		)

		writeJSON(
			w,
			http.StatusCreated,
			createPrivilegedIdentityResponse{
				Data: createPrivilegedIdentityResponseData{
					ID:            output.ID.String(),
					Email:         output.Email,
					Role:          string(output.Role),
					EmailVerified: false,
				},
			},
			logger,
		)
	}
}
