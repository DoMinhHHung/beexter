package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"

	appresetpassword "github.com/DoMinhHHung/beexster/service/identity/internal/application/resetpassword"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
)

type ResetPasswordExecutor interface {
	Execute(
		ctx context.Context,
		input appresetpassword.Input,
	) (appresetpassword.Output, error)
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type resetPasswordResponse struct {
	Data resetPasswordResponseData `json:"data"`
}

type resetPasswordResponseData struct {
	PasswordReset bool `json:"password_reset"`
}

func resetPasswordHandler(
	logger *slog.Logger,
	executor ResetPasswordExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New(
						"reset-password executor is not initialized",
					),
				),
				logger,
			)
			return
		}

		var request resetPasswordRequest
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
			appresetpassword.Input{
				Token:       request.Token,
				NewPassword: request.NewPassword,
				IPAddress:   ipAddress.Unmap(),
				RequestID:   requestID,
			},
		)
		if err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			resetPasswordResponse{
				Data: resetPasswordResponseData{
					PasswordReset: output.PasswordReset,
				},
			},
			logger,
		)
	}
}
