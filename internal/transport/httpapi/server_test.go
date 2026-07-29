package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealth(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)

	NewHandler(nil).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Body.String(); got != "{\"status\":\"ok\"}\n" {
		t.Fatalf("body = %q", got)
	}
}

func TestHealthRejectsUnsupportedMethod(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/health", nil)

	NewHandler(nil).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
	if got := recorder.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow = %q, want %q", got, http.MethodGet)
	}
}

func TestReady(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/ready", nil)

	NewHandler(func(context.Context) error { return nil }).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestReadyWhenDependencyCheckFails(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/ready", nil)

	NewHandler(func(context.Context) error {
		return errors.New("dependency unavailable")
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if got := recorder.Body.String(); got != "{\"status\":\"not_ready\"}\n" {
		t.Fatalf("body = %q", got)
	}
}
