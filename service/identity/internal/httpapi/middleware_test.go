package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestIDMiddleware(t *testing.T) {
	t.Parallel()

	logger := testLogger()

	handler := applyMiddleware(
		logger,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := requestIDFromContext(r.Context())
			if requestID == "" {
				t.Error("expected request ID in context")
			}

			w.WriteHeader(http.StatusNoContent)
		}),
	)

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusNoContent,
			response.Code,
		)
	}

	if response.Header().Get("X-Request-ID") == "" {
		t.Error("expected X-Request-ID response header")
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	t.Parallel()

	logger := testLogger()

	handler := applyMiddleware(
		logger,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("unexpected failure")
		}),
	)

	request := httptest.NewRequest(http.MethodGet, "/panic", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusInternalServerError,
			response.Code,
		)
	}

	var payload errorResponse

	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Error.Code != "ERR_INTERNAL" {
		t.Fatalf(
			"expected ERR_INTERNAL, got %s",
			payload.Error.Code,
		)
	}

	if payload.Error.RequestID == "" {
		t.Error("expected request ID in error response")
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	t.Parallel()

	logger := testLogger()

	handler := applyMiddleware(
		logger,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}

	for name, expected := range expectedHeaders {
		actual := response.Header().Get(name)
		if actual != expected {
			t.Errorf(
				"expected header %s=%q, got %q",
				name,
				expected,
				actual,
			)
		}
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}
