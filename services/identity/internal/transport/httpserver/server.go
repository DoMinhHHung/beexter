package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/DoMinhHHung/beexter/services/identity/internal/config"
)

type ReadinessCheck func(context.Context) error

type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
}

func New(cfg config.HTTPConfig, logger *slog.Logger, readinessCheck ReadinessCheck) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	return &Server{
		httpServer: &http.Server{
			Addr:              cfg.Address,
			Handler:           newHandler(logger, readinessCheck),
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
		},
		logger: logger,
	}
}

func (s *Server) Run() error {
	s.logger.Info("starting HTTP server", "address", s.httpServer.Addr)

	err := s.httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("listen and serve: %w", err)
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}

	return nil
}

func newHandler(logger *slog.Logger, readinessCheck ReadinessCheck) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(logger, w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		if readinessCheck == nil {
			writeJSON(logger, w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}

		if err := readinessCheck(r.Context()); err != nil {
			writeJSON(logger, w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}

		writeJSON(logger, w, http.StatusOK, map[string]string{"status": "ready"})
	})

	return mux
}

func writeJSON(logger *slog.Logger, w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logger.Error("encode HTTP response", "error", err)
	}
}
