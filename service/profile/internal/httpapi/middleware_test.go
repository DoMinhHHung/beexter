package httpapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPanicRecoveryReturnsSanitizedError(t *testing.T) {
	t.Parallel()

	const sensitivePanic = "database password super-secret"
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	panicHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(sensitivePanic)
	})

	var handler http.Handler = panicHandler
	handler = recoverPanics(logger, handler)
	handler = logAccess(logger, handler)
	handler = assignRequestID(handler)

	request := httptest.NewRequest(http.MethodGet, "/panic", nil)
	request.Header.Set(requestIDHeader, "panic-test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), sensitivePanic) || strings.Contains(logs.String(), sensitivePanic) {
		t.Fatalf("panic value was exposed: body=%q logs=%q", response.Body.String(), logs.String())
	}
	assertErrorBody(t, response.Body.String(), "internal_error", "panic-test")
}

func TestNewRejectsInvalidDependencies(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	checker := readinessFunc(func(context.Context) error { return nil })

	tests := []struct {
		name    string
		logger  *slog.Logger
		checker ReadinessChecker
		timeout time.Duration
	}{
		{name: "nil logger", logger: nil, checker: checker, timeout: time.Second},
		{name: "nil checker", logger: logger, checker: nil, timeout: time.Second},
		{name: "invalid timeout", logger: logger, checker: checker, timeout: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(test.logger, test.checker, test.timeout); err == nil {
				t.Fatal("New() error = nil")
			}
		})
	}
}

func TestResponseMetadataKeepsFirstStatus(t *testing.T) {
	t.Parallel()

	response := httptest.NewRecorder()
	metadata := &responseMetadata{ResponseWriter: response}
	metadata.WriteHeader(http.StatusCreated)
	metadata.WriteHeader(http.StatusInternalServerError)

	if _, err := metadata.Write([]byte("ok")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if response.Code != http.StatusCreated || metadata.status != http.StatusCreated {
		t.Fatalf("response status = %d, metadata status = %d", response.Code, metadata.status)
	}
	if metadata.bytes != 2 {
		t.Fatalf("response bytes = %d", metadata.bytes)
	}
}

func TestReadyCheckerErrorIsNotWrappedIntoResponse(t *testing.T) {
	t.Parallel()

	secretErr := errors.New("password=do-not-expose")
	handler := mustHandler(t, readinessFunc(func(context.Context) error {
		return secretErr
	}), time.Second, &bytes.Buffer{})

	response := performRequest(handler, http.MethodGet, "/ready", "sanitized-test")
	if strings.Contains(response.Body.String(), secretErr.Error()) {
		t.Fatalf("response exposes checker error: %s", response.Body.String())
	}
}
