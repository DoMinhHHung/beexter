package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"

	appforgotpassword "github.com/DoMinhHHung/beexter/service/identity/internal/application/forgotpassword"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

type ForgotPasswordExecutor interface {
	Execute(
		ctx context.Context,
		input appforgotpassword.Input,
	) (appforgotpassword.Output, error)
}

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type forgotPasswordResponse struct {
	Data forgotPasswordResponseData `json:"data"`
}

type forgotPasswordResponseData struct {
	Accepted bool `json:"accepted"`
}

func forgotPasswordHandler(
	logger *slog.Logger,
	executor ForgotPasswordExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("forgot-password executor is not initialized"),
				),
				logger,
			)
			return
		}

		var request forgotPasswordRequest
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
			appforgotpassword.Input{
				Email:     request.Email,
				Locale:    parseAcceptLanguage(r.Header.Get("Accept-Language")),
				IPAddress: ipAddress.Unmap(),
				RequestID: requestID,
			},
		)
		if err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		writeJSON(
			w,
			http.StatusAccepted,
			forgotPasswordResponse{
				Data: forgotPasswordResponseData{
					Accepted: output.Accepted,
				},
			},
			logger,
		)
	}
}
