package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type ReadinessChecker interface {
	Ping(context.Context) error
}

type API struct {
	readiness        ReadinessChecker
	readinessTimeout time.Duration
}

func New(
	logger *slog.Logger,
	readiness ReadinessChecker,
	readinessTimeout time.Duration,
) (http.Handler, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if readiness == nil {
		return nil, fmt.Errorf("readiness checker is required")
	}
	if readinessTimeout <= 0 {
		return nil, fmt.Errorf("readiness timeout must be positive")
	}

	api := &API{
		readiness:        readiness,
		readinessTimeout: readinessTimeout,
	}

	var handler http.Handler = api
	handler = recoverPanics(logger, handler)
	handler = logAccess(logger, handler)
	handler = assignRequestID(handler)
	return handler, nil
}

func (api *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/health":
		api.serveGET(w, r, api.health)
	case "/ready":
		api.serveGET(w, r, api.ready)
	default:
		writeError(w, r, http.StatusNotFound, "not_found", "resource not found")
	}
}

func (api *API) serveGET(
	w http.ResponseWriter,
	r *http.Request,
	handler http.HandlerFunc,
) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(
			w,
			r,
			http.StatusMethodNotAllowed,
			"method_not_allowed",
			"method not allowed",
		)
		return
	}

	handler.ServeHTTP(w, r)
}

func (*API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func (api *API) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), api.readinessTimeout)
	defer cancel()

	if err := api.readiness.Ping(ctx); err != nil {
		writeError(
			w,
			r,
			http.StatusServiceUnavailable,
			"dependency_unavailable",
			"service is not ready",
		)
		return
	}

	writeJSON(w, http.StatusOK, statusResponse{Status: "ready"})
}
