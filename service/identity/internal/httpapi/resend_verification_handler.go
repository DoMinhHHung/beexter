package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"

	appresendverification "github.com/DoMinhHHung/beexster/service/identity/internal/application/resendverification"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
)

type ResendVerificationExecutor interface {
	Execute(
		ctx context.Context,
		input appresendverification.Input,
	) (appresendverification.Output, error)
}

type resendVerificationRequest struct {
	Email string `json:"email"`
}

type resendVerificationResponse struct {
	Data resendVerificationResponseData `json:"data"`
}

type resendVerificationResponseData struct {
	Accepted bool `json:"accepted"`
}

func resendVerificationHandler(
	logger *slog.Logger,
	executor ResendVerificationExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("resend-verification executor is not initialized"),
				),
				logger,
			)
			return
		}

		var request resendVerificationRequest
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
			appresendverification.Input{
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
			resendVerificationResponse{
				Data: resendVerificationResponseData{
					Accepted: output.Accepted,
				},
			},
			logger,
		)
	}
}
