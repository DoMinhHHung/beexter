package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	appdeleteaccount "github.com/DoMinhHHung/beexter/service/identity/internal/application/deleteaccount"
	appreactivation "github.com/DoMinhHHung/beexter/service/identity/internal/application/requestreactivation"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func TestDeleteAccountHandlerUsesAuthenticatedIdentity(t *testing.T) {
	t.Parallel()
	logger := lifecycleTestLogger()
	executor := deleteAccountExecutorFunc(func(_ context.Context, input appdeleteaccount.Input) (appdeleteaccount.Output, error) {
		if input.UserID.String() != "0198f124-659f-7cbd-a441-dc7eea175073" ||
			input.CurrentPassword != "Secure1!" {
			t.Fatalf("unexpected input: %+v", input)
		}
		return appdeleteaccount.Output{Deleted: true, SoftDeleteCount: 1}, nil
	})
	handler := applyMiddleware(logger, deleteAccountHandler(logger, executor))

	request := httptest.NewRequest(
		http.MethodDelete,
		"/v1/me",
		strings.NewReader(`{"current_password":"Secure1!"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.10:1234"
	request = request.WithContext(context.WithValue(
		request.Context(),
		authenticatedPrincipalContextKey{},
		appauth.Principal{UserID: identity.ID("0198f124-659f-7cbd-a441-dc7eea175073")},
	))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
}

func TestReactivationHandlerReturnsGenericAccepted(t *testing.T) {
	t.Parallel()
	logger := lifecycleTestLogger()
	executor := reactivationExecutorFunc(func(_ context.Context, input appreactivation.Input) (appreactivation.Output, error) {
		if input.Locale != "vi" || input.Email != "user@example.com" {
			t.Fatalf("unexpected input: %+v", input)
		}
		return appreactivation.Output{Accepted: true}, nil
	})
	handler := applyMiddleware(logger, requestReactivationHandler(logger, executor))
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/request-reactivation",
		strings.NewReader(`{"email":"user@example.com","password":"Secure1!"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept-Language", "vi-VN")
	request.RemoteAddr = "192.0.2.10:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", response.Code, response.Body.String())
	}
	var payload reactivationResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil || !payload.Data.Accepted {
		t.Fatalf("unexpected response: %+v err=%v", payload, err)
	}
}

type deleteAccountExecutorFunc func(context.Context, appdeleteaccount.Input) (appdeleteaccount.Output, error)

func (f deleteAccountExecutorFunc) Execute(ctx context.Context, input appdeleteaccount.Input) (appdeleteaccount.Output, error) {
	return f(ctx, input)
}

type reactivationExecutorFunc func(context.Context, appreactivation.Input) (appreactivation.Output, error)

func (f reactivationExecutorFunc) Execute(ctx context.Context, input appreactivation.Input) (appreactivation.Output, error) {
	return f(ctx, input)
}

func lifecycleTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
