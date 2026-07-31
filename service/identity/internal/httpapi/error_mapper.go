package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain"
)

type errorMapping struct {
	statusCode int
	message    string
}

var domainErrorMappings = map[domain.ErrorCode]errorMapping{
	domain.ErrInvalidInput: {
		statusCode: http.StatusBadRequest,
		message:    "invalid input",
	},
	domain.ErrEmailAlreadyExists: {
		statusCode: http.StatusConflict,
		message:    "email already exists",
	},
	domain.ErrInvalidCredentials: {
		statusCode: http.StatusUnauthorized,
		message:    "invalid credentials",
	},
	domain.ErrEmailNotVerified: {
		statusCode: http.StatusForbidden,
		message:    "email is not verified",
	},
	domain.ErrAccountInactive: {
		statusCode: http.StatusForbidden,
		message:    "account is inactive",
	},
	domain.ErrTokenInvalid: {
		statusCode: http.StatusUnauthorized,
		message:    "token is invalid",
	},
	domain.ErrTokenExpired: {
		statusCode: http.StatusUnauthorized,
		message:    "token has expired",
	},
	domain.ErrTokenReuseDetected: {
		statusCode: http.StatusUnauthorized,
		message:    "token reuse detected",
	},
	domain.ErrNotFound: {
		statusCode: http.StatusNotFound,
		message:    "resource not found",
	},
	domain.ErrForbidden: {
		statusCode: http.StatusForbidden,
		message:    "forbidden",
	},
	domain.ErrRateLimited: {
		statusCode: http.StatusTooManyRequests,
		message:    "too many requests",
	},
	domain.ErrInternal: {
		statusCode: http.StatusInternalServerError,
		message:    "internal server error",
	},
}

func writeApplicationError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
	logger *slog.Logger,
) {
	requestID := requestIDFromContext(r.Context())

	var domainError *domain.Error
	if !errors.As(err, &domainError) {
		logger.Error(
			"unhandled application error",
			slog.String("request_id", requestID),
			slog.String("error", err.Error()),
		)

		writeError(
			w,
			http.StatusInternalServerError,
			string(domain.ErrInternal),
			"internal server error",
			requestID,
			logger,
		)

		return
	}

	mapping, exists := domainErrorMappings[domainError.Code]
	if !exists {
		logger.Error(
			"unmapped domain error",
			slog.String("request_id", requestID),
			slog.String("code", string(domainError.Code)),
		)

		writeError(
			w,
			http.StatusInternalServerError,
			string(domain.ErrInternal),
			"internal server error",
			requestID,
			logger,
		)

		return
	}

	if domainError.Code == domain.ErrInternal {
		attributes := []any{
			slog.String("request_id", requestID),
			slog.String("code", string(domainError.Code)),
		}

		if domainError.Cause != nil {
			attributes = append(
				attributes,
				slog.String("error", domainError.Cause.Error()),
			)
		}

		logger.Error("internal application error", attributes...)
	}

	writeError(
		w,
		mapping.statusCode,
		string(domainError.Code),
		mapping.message,
		requestID,
		logger,
	)
}
