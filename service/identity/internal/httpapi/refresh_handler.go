package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	apprefresh "github.com/DoMinhHHung/beexster/service/identity/internal/application/refresh"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
)

type RefreshExecutor interface {
	Execute(
		ctx context.Context,
		input apprefresh.Input,
	) (apprefresh.Output, error)
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshResponse struct {
	Data refreshResponseData `json:"data"`
}

type refreshResponseData struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	TokenType             string `json:"token_type"`
	AccessTokenExpiresAt  string `json:"access_token_expires_at"`
	RefreshTokenExpiresAt string `json:"refresh_token_expires_at"`
	DeviceID              string `json:"device_id"`
}

func refreshHandler(
	logger *slog.Logger,
	executor RefreshExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("refresh executor is not initialized"),
				),
				logger,
			)
			return
		}

		var request refreshRequest
		if err := decodeJSONBody(w, r, &request); err != nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(domain.ErrInvalidInput, err),
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
			apprefresh.Input{
				RefreshToken: request.RefreshToken,
				IPAddress:    ipAddress.Unmap(),
				UserAgent:    r.UserAgent(),
			},
		)
		if err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			refreshResponse{
				Data: refreshResponseData{
					AccessToken:           output.AccessToken,
					RefreshToken:          output.RefreshToken,
					TokenType:             output.TokenType,
					AccessTokenExpiresAt:  output.AccessTokenExpiresAt.Format(time.RFC3339Nano),
					RefreshTokenExpiresAt: output.RefreshTokenExpiresAt.Format(time.RFC3339Nano),
					DeviceID:              output.DeviceID,
				},
			},
			logger,
		)
	}
}
