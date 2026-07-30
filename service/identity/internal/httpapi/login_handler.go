package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	applogin "github.com/DoMinhHHung/beexter/service/identity/internal/application/login"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

type LoginExecutor interface {
	Execute(
		ctx context.Context,
		input applogin.Input,
	) (applogin.Output, error)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Data loginResponseData `json:"data"`
}

type loginResponseData struct {
	AccessToken           string            `json:"access_token"`
	RefreshToken          string            `json:"refresh_token"`
	TokenType             string            `json:"token_type"`
	AccessTokenExpiresAt  string            `json:"access_token_expires_at"`
	RefreshTokenExpiresAt string            `json:"refresh_token_expires_at"`
	DeviceID              string            `json:"device_id"`
	User                  loginResponseUser `json:"user"`
}

type loginResponseUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Role          string `json:"role"`
	EmailVerified bool   `json:"email_verified"`
}

func loginHandler(
	logger *slog.Logger,
	executor LoginExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("login executor is not initialized"),
				),
				logger,
			)
			return
		}

		var request loginRequest
		if err := decodeJSONBody(w, r, &request); err != nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInvalidInput,
					err,
				),
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
			applogin.Input{
				Email:     request.Email,
				Password:  request.Password,
				IPAddress: ipAddress.Unmap(),
				UserAgent: r.UserAgent(),
				RequestID: requestID,
			},
		)
		if err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			loginResponse{
				Data: loginResponseData{
					AccessToken:           output.AccessToken,
					RefreshToken:          output.RefreshToken,
					TokenType:             output.TokenType,
					AccessTokenExpiresAt:  output.AccessTokenExpiresAt.Format(time.RFC3339),
					RefreshTokenExpiresAt: output.RefreshTokenExpiresAt.Format(time.RFC3339),
					DeviceID:              output.DeviceID,
					User: loginResponseUser{
						ID:            output.User.ID.String(),
						Email:         output.User.Email,
						Role:          string(output.User.Role),
						EmailVerified: output.User.EmailVerified,
					},
				},
			},
			logger,
		)
	}
}
