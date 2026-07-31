package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	apploginhistory "github.com/DoMinhHHung/beexter/service/identity/internal/application/loginhistory"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

type LoginHistoryExecutor interface {
	Execute(
		ctx context.Context,
		input apploginhistory.Input,
	) (apploginhistory.Output, error)
}

type loginHistoryResponse struct {
	Data loginHistoryResponseData `json:"data"`
}

type loginHistoryResponseData struct {
	Attempts   []loginHistoryAttempt `json:"attempts"`
	NextBefore *string               `json:"next_before,omitempty"`
}

type loginHistoryAttempt struct {
	ID          string `json:"id"`
	Success     bool   `json:"success"`
	FailureCode string `json:"failure_code,omitempty"`
	IPAddress   string `json:"ip_address"`
	UserAgent   string `json:"user_agent"`
	AttemptedAt string `json:"attempted_at"`
}

func loginHistoryHandler(
	logger *slog.Logger,
	executor LoginHistoryExecutor,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if executor == nil {
			writeApplicationError(
				w,
				r,
				domain.WrapError(
					domain.ErrInternal,
					errors.New("login-history executor is not initialized"),
				),
				logger,
			)
			return
		}

		principal, ok := authenticatedPrincipalFromContext(r.Context())
		if !ok || principal.UserID.IsZero() {
			writeApplicationError(w, r, domain.NewError(domain.ErrTokenInvalid), logger)
			return
		}

		limit, before, err := parseLoginHistoryQuery(r)
		if err != nil {
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
			apploginhistory.Input{
				UserID: principal.UserID,
				Limit:  limit,
				Before: before,
			},
		)
		if err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		attempts := make([]loginHistoryAttempt, 0, len(output.Attempts))
		for _, attempt := range output.Attempts {
			attempts = append(attempts, loginHistoryAttempt{
				ID:          attempt.ID,
				Success:     attempt.Success,
				FailureCode: attempt.FailureCode,
				IPAddress:   attempt.IPAddress.String(),
				UserAgent:   attempt.UserAgent,
				AttemptedAt: attempt.AttemptedAt.UTC().Format(time.RFC3339Nano),
			})
		}

		var nextBefore *string
		if output.NextBefore != nil {
			formatted := output.NextBefore.UTC().Format(time.RFC3339Nano)
			nextBefore = &formatted
		}

		writeJSON(
			w,
			http.StatusOK,
			loginHistoryResponse{Data: loginHistoryResponseData{
				Attempts:   attempts,
				NextBefore: nextBefore,
			}},
			logger,
		)
	}
}

func parseLoginHistoryQuery(r *http.Request) (int, *time.Time, error) {
	limit := 0
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil {
			return 0, nil, errors.New("limit must be an integer")
		}
		limit = parsed
	}

	var before *time.Time
	if rawBefore := strings.TrimSpace(r.URL.Query().Get("before")); rawBefore != "" {
		parsed, err := time.Parse(time.RFC3339Nano, rawBefore)
		if err != nil {
			return 0, nil, errors.New("before must be RFC3339")
		}
		parsed = parsed.UTC()
		before = &parsed
	}
	return limit, before, nil
}
