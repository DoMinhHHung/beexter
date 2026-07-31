package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	appverifyemail "github.com/DoMinhHHung/beexter/service/identity/internal/application/verifyemail"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

type VerifyEmailExecutor interface {
	Execute(
		ctx context.Context,
		input appverifyemail.Input,
	) (appverifyemail.Output, error)
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

type verifyEmailResponse struct {
	Data verifyEmailResponseData `json:"data"`
}

type verifyEmailResponseData struct {
	EmailVerified bool `json:"email_verified"`
	Reactivated   bool `json:"reactivated"`
}

func verifyEmailHandler(
	logger *slog.Logger,
	executor VerifyEmailExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("verify-email executor is not initialized"),
				),
				logger,
			)
			return
		}

		var request verifyEmailRequest
		if err := decodeJSONBody(w, r, &request); err != nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(domain.ErrInvalidInput, err),
				logger,
			)
			return
		}

		output, err := executor.Execute(
			r.Context(),
			appverifyemail.Input{Token: request.Token},
		)
		if err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			verifyEmailResponse{Data: verifyEmailResponseData{
				EmailVerified: output.EmailVerified,
				Reactivated:   output.Reactivated,
			}},
			logger,
		)
	}
}
