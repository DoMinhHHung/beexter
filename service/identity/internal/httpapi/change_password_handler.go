package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"

	appchangepassword "github.com/DoMinhHHung/beexster/service/identity/internal/application/changepassword"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
)

type ChangePasswordExecutor interface {
	Execute(
		ctx context.Context,
		input appchangepassword.Input,
	) (appchangepassword.Output, error)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type changePasswordResponse struct {
	Data changePasswordResponseData `json:"data"`
}

type changePasswordResponseData struct {
	PasswordChanged bool `json:"password_changed"`
}

func changePasswordHandler(
	logger *slog.Logger,
	executor ChangePasswordExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("change-password executor is not initialized"),
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
					errors.New("authenticated principal is missing"),
				),
				logger,
			)
			return
		}

		var request changePasswordRequest
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

		ipAddress, err := netip.ParseAddr(remoteIP(r.RemoteAddr))
		if err != nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					fmt.Errorf("parse remote IP address: %w", err),
				),
				logger,
			)
			return
		}

		output, err := executor.Execute(
			r.Context(),
			appchangepassword.Input{
				UserID:          principal.UserID,
				CurrentPassword: request.CurrentPassword,
				NewPassword:     request.NewPassword,
				IPAddress:       ipAddress.Unmap(),
				RequestID:       requestID,
			},
		)
		if err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			changePasswordResponse{
				Data: changePasswordResponseData{
					PasswordChanged: output.PasswordChanged,
				},
			},
			logger,
		)
	}
}
