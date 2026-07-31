package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"

	appdeleteaccount "github.com/DoMinhHHung/beexter/service/identity/internal/application/deleteaccount"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

type DeleteAccountExecutor interface {
	Execute(
		ctx context.Context,
		input appdeleteaccount.Input,
	) (appdeleteaccount.Output, error)
}

type deleteAccountRequest struct {
	CurrentPassword string `json:"current_password"`
}

type deleteAccountResponse struct {
	Data deleteAccountResponseData `json:"data"`
}

type deleteAccountResponseData struct {
	Deleted         bool  `json:"deleted"`
	HardDeleted     bool  `json:"hard_deleted"`
	SoftDeleteCount uint8 `json:"soft_delete_count"`
}

func deleteAccountHandler(
	logger *slog.Logger,
	executor DeleteAccountExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("delete-account executor is not initialized"),
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
				domain.NewError(domain.ErrTokenInvalid),
				logger,
			)
			return
		}

		var request deleteAccountRequest
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
			appdeleteaccount.Input{
				UserID:          principal.UserID,
				CurrentPassword: request.CurrentPassword,
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
			deleteAccountResponse{Data: deleteAccountResponseData{
				Deleted:         output.Deleted,
				HardDeleted:     output.HardDeleted,
				SoftDeleteCount: output.SoftDeleteCount,
			}},
			logger,
		)
	}
}
