package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const readinessTimeout = 2 * time.Second

var errReadinessNotConfigured = errors.New("readiness check is not configured")

type ReadinessCheck func(context.Context) error

type statusResponse struct {
	Status string `json:"status"`
}

func NewHandler(readinessCheck ReadinessCheck) http.Handler {
	if readinessCheck == nil {
		readinessCheck = func(context.Context) error {
			return errReadinessNotConfigured
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/ready", readyHandler(readinessCheck))
	return mux
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func readyHandler(check ReadinessCheck) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()

		if err := check(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, statusResponse{Status: "not_ready"})
			return
		}
		writeJSON(w, http.StatusOK, statusResponse{Status: "ready"})
	}
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeJSON(w, http.StatusMethodNotAllowed, statusResponse{Status: "method_not_allowed"})
	return false
}

func writeJSON(w http.ResponseWriter, statusCode int, body statusResponse) {
	payload, err := json.Marshal(body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	payload = append(payload, '\n')

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if _, err := w.Write(payload); err != nil {
		return
	}
}
