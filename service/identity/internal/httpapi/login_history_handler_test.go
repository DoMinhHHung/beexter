package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	apploginhistory "github.com/DoMinhHHung/beexster/service/identity/internal/application/loginhistory"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

func TestLoginHistoryHandlerParsesCursor(t *testing.T) {
	t.Parallel()
	logger := lifecycleTestLogger()
	before := time.Date(2026, time.July, 31, 1, 2, 3, 0, time.UTC)
	executor := loginHistoryExecutorFunc(func(_ context.Context, input apploginhistory.Input) (apploginhistory.Output, error) {
		if input.Limit != 10 || input.Before == nil || !input.Before.Equal(before) {
			t.Fatalf("unexpected input: %+v", input)
		}
		return apploginhistory.Output{Attempts: []apploginhistory.Attempt{{
			ID:          "0198f124-659f-7cbd-a441-dc7eea175074",
			Success:     true,
			IPAddress:   netip.MustParseAddr("192.0.2.10"),
			UserAgent:   "test",
			AttemptedAt: before.Add(-time.Minute),
		}}}, nil
	})
	handler := loginHistoryHandler(logger, executor)
	request := httptest.NewRequest(
		http.MethodGet,
		"/v1/me/login-history?limit=10&before="+before.Format(time.RFC3339),
		nil,
	)
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

type loginHistoryExecutorFunc func(context.Context, apploginhistory.Input) (apploginhistory.Output, error)

func (f loginHistoryExecutorFunc) Execute(ctx context.Context, input apploginhistory.Input) (apploginhistory.Output, error) {
	return f(ctx, input)
}
