package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
)

func TestWriteApplicationError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedCode   string
	}{
		{
			name:           "invalid input",
			err:            domain.NewError(domain.ErrInvalidInput),
			expectedStatus: http.StatusBadRequest,
			expectedCode:   string(domain.ErrInvalidInput),
		},
		{
			name: "email already exists",
			err: domain.NewError(
				domain.ErrEmailAlreadyExists,
			),
			expectedStatus: http.StatusConflict,
			expectedCode:   string(domain.ErrEmailAlreadyExists),
		},
		{
			name: "invalid credentials",
			err: domain.NewError(
				domain.ErrInvalidCredentials,
			),
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   string(domain.ErrInvalidCredentials),
		},
		{
			name: "email not verified",
			err: domain.NewError(
				domain.ErrEmailNotVerified,
			),
			expectedStatus: http.StatusForbidden,
			expectedCode:   string(domain.ErrEmailNotVerified),
		},
		{
			name: "account inactive",
			err: domain.NewError(
				domain.ErrAccountInactive,
			),
			expectedStatus: http.StatusForbidden,
			expectedCode:   string(domain.ErrAccountInactive),
		},
		{
			name: "token invalid",
			err: domain.NewError(
				domain.ErrTokenInvalid,
			),
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   string(domain.ErrTokenInvalid),
		},
		{
			name: "token expired",
			err: domain.NewError(
				domain.ErrTokenExpired,
			),
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   string(domain.ErrTokenExpired),
		},
		{
			name: "token reuse detected",
			err: domain.NewError(
				domain.ErrTokenReuseDetected,
			),
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   string(domain.ErrTokenReuseDetected),
		},
		{
			name:           "not found",
			err:            domain.NewError(domain.ErrNotFound),
			expectedStatus: http.StatusNotFound,
			expectedCode:   string(domain.ErrNotFound),
		},
		{
			name:           "forbidden",
			err:            domain.NewError(domain.ErrForbidden),
			expectedStatus: http.StatusForbidden,
			expectedCode:   string(domain.ErrForbidden),
		},
		{
			name: "rate limited",
			err: domain.NewError(
				domain.ErrRateLimited,
			),
			expectedStatus: http.StatusTooManyRequests,
			expectedCode:   string(domain.ErrRateLimited),
		},
		{
			name: "internal error",
			err: domain.WrapError(
				domain.ErrInternal,
				errors.New("database unavailable"),
			),
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   string(domain.ErrInternal),
		},
		{
			name:           "unknown error",
			err:            errors.New("unexpected failure"),
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   string(domain.ErrInternal),
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(
				http.MethodPost,
				"/test",
				nil,
			)

			ctx := context.WithValue(
				request.Context(),
				requestIDContextKey{},
				"test-request-id",
			)

			request = request.WithContext(ctx)
			response := httptest.NewRecorder()

			writeApplicationError(
				response,
				request,
				test.err,
				testLogger(),
			)

			if response.Code != test.expectedStatus {
				t.Fatalf(
					"expected status %d, got %d",
					test.expectedStatus,
					response.Code,
				)
			}

			var payload errorResponse

			if err := json.NewDecoder(
				response.Body,
			).Decode(&payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			if payload.Error.Code != test.expectedCode {
				t.Fatalf(
					"expected code %q, got %q",
					test.expectedCode,
					payload.Error.Code,
				)
			}

			if payload.Error.RequestID != "test-request-id" {
				t.Fatalf(
					"expected request ID %q, got %q",
					"test-request-id",
					payload.Error.RequestID,
				)
			}
		})
	}
}
