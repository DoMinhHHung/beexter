package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"

	appsignup "github.com/DoMinhHHung/beexter/service/identity/internal/application/signup"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

type SignupExecutor interface {
	Execute(
		ctx context.Context,
		input appsignup.Input,
	) (appsignup.Output, error)
}

type signupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type signupResponse struct {
	Data signupResponseData `json:"data"`
}

type signupResponseData struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func signupHandler(
	logger *slog.Logger,
	executor SignupExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("signup executor is not initialized"),
				),
				logger,
			)
			return
		}

		var request signupRequest
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
			appsignup.Input{
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
			http.StatusCreated,
			signupResponse{
				Data: signupResponseData{
					ID:            output.ID.String(),
					Email:         output.Email,
					EmailVerified: false,
				},
			},
			logger,
		)
	}
}
