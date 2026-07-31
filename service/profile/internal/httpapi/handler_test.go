package httpapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type readinessFunc func(context.Context) error

func (fn readinessFunc) Ping(ctx context.Context) error {
	return fn(ctx)
}

func TestHealthIsLivenessOnly(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	handler := mustHandler(t, readinessFunc(func(context.Context) error {
		calls.Add(1)
		return errors.New("must not be called")
	}), time.Second, io.Discard)

	response := performRequest(handler, http.MethodGet, "/health", "health-test")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("readiness checker calls = %d", calls.Load())
	}
	if response.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatalf("body = %q", response.Body.String())
	}
}

func TestReadySuccess(t *testing.T) {
	t.Parallel()

	handler := mustHandler(t, readinessFunc(func(context.Context) error {
		return nil
	}), time.Second, io.Discard)

	response := performRequest(handler, http.MethodGet, "/ready", "ready-success")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Body.String() != "{\"status\":\"ready\"}\n" {
		t.Fatalf("body = %q", response.Body.String())
	}
}

func TestReadyDependencyFailureIsSanitized(t *testing.T) {
	t.Parallel()

	const sensitiveError = "postgres://profile:super-secret@database.internal/profile"
	handler := mustHandler(t, readinessFunc(func(context.Context) error {
		return errors.New(sensitiveError)
	}), time.Second, io.Discard)

	response := performRequest(handler, http.MethodGet, "/ready", "ready-failure")

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "super-secret") || strings.Contains(response.Body.String(), "database.internal") {
		t.Fatalf("response exposes dependency error: %s", response.Body.String())
	}
	assertErrorBody(t, response.Body.String(), "dependency_unavailable", "ready-failure")
}

func TestReadyTimeout(t *testing.T) {
	t.Parallel()

	deadlineObserved := make(chan struct{}, 1)
	handler := mustHandler(t, readinessFunc(func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			return errors.New("missing readiness deadline")
		}
		<-ctx.Done()
		deadlineObserved <- struct{}{}
		return ctx.Err()
	}), 20*time.Millisecond, io.Discard)

	started := time.Now()
	response := performRequest(handler, http.MethodGet, "/ready", "ready-timeout")
	elapsed := time.Since(started)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if elapsed > time.Second {
		t.Fatalf("readiness timeout took %s", elapsed)
	}
	select {
	case <-deadlineObserved:
	case <-time.After(time.Second):
		t.Fatal("readiness checker did not observe cancellation")
	}
}

func TestRouterMethodAndPathBehavior(t *testing.T) {
	t.Parallel()

	handler := mustHandler(t, readinessFunc(func(context.Context) error { return nil }), time.Second, io.Discard)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantCode   string
		wantAllow  string
	}{
		{name: "unknown path", method: http.MethodGet, path: "/unknown", wantStatus: http.StatusNotFound, wantCode: "not_found"},
		{name: "trailing slash", method: http.MethodGet, path: "/health/", wantStatus: http.StatusNotFound, wantCode: "not_found"},
		{name: "health method", method: http.MethodPost, path: "/health", wantStatus: http.StatusMethodNotAllowed, wantCode: "method_not_allowed", wantAllow: http.MethodGet},
		{name: "ready method", method: http.MethodDelete, path: "/ready", wantStatus: http.StatusMethodNotAllowed, wantCode: "method_not_allowed", wantAllow: http.MethodGet},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			response := performRequest(handler, test.method, test.path, "router-test")
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if response.Header().Get("Allow") != test.wantAllow {
				t.Fatalf("Allow = %q", response.Header().Get("Allow"))
			}
			assertErrorBody(t, response.Body.String(), test.wantCode, "router-test")
		})
	}
}

func TestRequestIDHandling(t *testing.T) {
	t.Parallel()

	handler := mustHandler(t, readinessFunc(func(context.Context) error { return nil }), time.Second, io.Discard)

	valid := performRequest(handler, http.MethodGet, "/health", "caller-123")
	if valid.Header().Get(requestIDHeader) != "caller-123" {
		t.Fatalf("valid request ID = %q", valid.Header().Get(requestIDHeader))
	}

	invalid := performRequest(handler, http.MethodGet, "/health", "bad\nrequest-id")
	generated := invalid.Header().Get(requestIDHeader)
	if generated == "" || generated == "bad\nrequest-id" || !validRequestID(generated) {
		t.Fatalf("generated request ID = %q", generated)
	}
}

func TestStructuredAccessLogging(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	handler := mustHandler(t, readinessFunc(func(context.Context) error { return nil }), time.Second, &logs)

	response := performRequest(handler, http.MethodGet, "/health", "log-test")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}

	logLine := logs.String()
	for _, expected := range []string{
		`"msg":"HTTP request completed"`,
		`"request_id":"log-test"`,
		`"method":"GET"`,
		`"path":"/health"`,
		`"status":200`,
	} {
		if !strings.Contains(logLine, expected) {
			t.Fatalf("log %q does not contain %q", logLine, expected)
		}
	}
}

func mustHandler(
	t *testing.T,
	readiness ReadinessChecker,
	timeout time.Duration,
	logOutput io.Writer,
) http.Handler {
	t.Helper()

	logger := slog.New(slog.NewJSONHandler(logOutput, nil))
	handler, err := New(logger, readiness, timeout)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return handler
}

func performRequest(handler http.Handler, method, path, requestID string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	if requestID != "" {
		request.Header.Set(requestIDHeader, requestID)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertErrorBody(t *testing.T, body, code, requestID string) {
	t.Helper()

	if !strings.Contains(body, `"code":"`+code+`"`) {
		t.Fatalf("body %q does not contain code %q", body, code)
	}
	if !strings.Contains(body, `"request_id":"`+requestID+`"`) {
		t.Fatalf("body %q does not contain request ID %q", body, requestID)
	}
}
