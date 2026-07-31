package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	getmeapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/getme"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

type GetMeExecutor interface {
	Execute(
		ctx context.Context,
		input getmeapp.Input,
	) (getmeapp.Output, error)
}

type meResponse struct {
	Data meResponseData `json:"data"`
}

type meResponseData struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	PlatformRole  string    `json:"platform_role,omitempty"`
	Status        string    `json:"status"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func meHandler(
	logger *slog.Logger,
	executor GetMeExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("get-me executor is not initialized"),
				),
				logger,
			)
			return
		}

		principal, ok := authenticatedPrincipalFromContext(r.Context())
		if !ok || principal.UserID.IsZero() {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("authenticated principal is missing from context"),
				),
				logger,
			)
			return
		}

		output, err := executor.Execute(
			r.Context(),
			getmeapp.Input{UserID: principal.UserID},
		)
		if err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			meResponse{
				Data: meResponseData{
					ID:            output.ID.String(),
					Email:         output.Email,
					PlatformRole:  string(output.PlatformRole),
					Status:        string(output.Status),
					EmailVerified: output.EmailVerified,
					CreatedAt:     output.CreatedAt,
					UpdatedAt:     output.UpdatedAt,
				},
			},
			logger,
		)
	}
}
