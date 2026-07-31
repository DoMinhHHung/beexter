package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"

	appreactivation "github.com/DoMinhHHung/beexster/service/identity/internal/application/requestreactivation"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
)

type ReactivationExecutor interface {
	Execute(
		ctx context.Context,
		input appreactivation.Input,
	) (appreactivation.Output, error)
}

type reactivationRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type reactivationResponse struct {
	Data reactivationResponseData `json:"data"`
}

type reactivationResponseData struct {
	Accepted bool `json:"accepted"`
}

func requestReactivationHandler(
	logger *slog.Logger,
	executor ReactivationExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("reactivation executor is not initialized"),
				),
				logger,
			)
			return
		}

		var request reactivationRequest
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
			appreactivation.Input{
				Email:     request.Email,
				Password:  request.Password,
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
			reactivationResponse{Data: reactivationResponseData{
				Accepted: output.Accepted,
			}},
			logger,
		)
	}
}
