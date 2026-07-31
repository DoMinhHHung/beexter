package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	sessionmanagementapp "github.com/DoMinhHHung/beexster/service/identity/internal/application/sessionmanagement"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
)

type SessionManager interface {
	LogoutCurrent(
		ctx context.Context,
		principal appauth.Principal,
	) error

	LogoutAll(
		ctx context.Context,
		principal appauth.Principal,
	) error

	List(
		ctx context.Context,
		principal appauth.Principal,
	) ([]sessionmanagementapp.Session, error)

	Revoke(
		ctx context.Context,
		principal appauth.Principal,
		deviceID string,
	) error
}

type sessionsResponse struct {
	Data sessionsResponseData `json:"data"`
}

type sessionsResponseData struct {
	Sessions []sessionResponseItem `json:"sessions"`
}

type sessionResponseItem struct {
	DeviceID   string `json:"device_id"`
	UserAgent  string `json:"user_agent"`
	IPAddress  string `json:"ip_address"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
	LastUsedAt string `json:"last_used_at"`
	Current    bool   `json:"current"`
}

func logoutCurrentHandler(
	logger *slog.Logger,
	manager SessionManager,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := authenticatedPrincipalFromContext(r.Context())
		if !ok {
			writeMissingPrincipal(w, r, logger)
			return
		}

		if manager == nil {
			writeMissingSessionManager(w, r, logger)
			return
		}

		if err := manager.LogoutCurrent(
			r.Context(),
			principal,
		); err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func logoutAllHandler(
	logger *slog.Logger,
	manager SessionManager,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := authenticatedPrincipalFromContext(r.Context())
		if !ok {
			writeMissingPrincipal(w, r, logger)
			return
		}

		if manager == nil {
			writeMissingSessionManager(w, r, logger)
			return
		}

		if err := manager.LogoutAll(
			r.Context(),
			principal,
		); err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func listSessionsHandler(
	logger *slog.Logger,
	manager SessionManager,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := authenticatedPrincipalFromContext(r.Context())
		if !ok {
			writeMissingPrincipal(w, r, logger)
			return
		}

		if manager == nil {
			writeMissingSessionManager(w, r, logger)
			return
		}

		sessions, err := manager.List(r.Context(), principal)
		if err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		items := make([]sessionResponseItem, 0, len(sessions))
		for _, session := range sessions {
			items = append(items, sessionResponseItem{
				DeviceID:   session.DeviceID,
				UserAgent:  session.UserAgent,
				IPAddress:  session.IPAddress,
				CreatedAt:  session.CreatedAt.Format(time.RFC3339),
				ExpiresAt:  session.ExpiresAt.Format(time.RFC3339),
				LastUsedAt: session.LastUsedAt.Format(time.RFC3339),
				Current:    session.Current,
			})
		}

		writeJSON(
			w,
			http.StatusOK,
			sessionsResponse{
				Data: sessionsResponseData{Sessions: items},
			},
			logger,
		)
	}
}

func revokeSessionHandler(
	logger *slog.Logger,
	manager SessionManager,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := authenticatedPrincipalFromContext(r.Context())
		if !ok {
			writeMissingPrincipal(w, r, logger)
			return
		}

		if manager == nil {
			writeMissingSessionManager(w, r, logger)
			return
		}

		if err := manager.Revoke(
			r.Context(),
			principal,
			r.PathValue("device_id"),
		); err != nil {
			writeApplicationError(w, r, err, logger)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func writeMissingPrincipal(
	w http.ResponseWriter,
	r *http.Request,
	logger *slog.Logger,
) {
	writeApplicationError(
		w,
		r,
		domain.WrapError(
			domain.ErrInternal,
			errors.New("authenticated principal is missing from context"),
		),
		logger,
	)
}

func writeMissingSessionManager(
	w http.ResponseWriter,
	r *http.Request,
	logger *slog.Logger,
) {
	writeApplicationError(
		w,
		r,
		domain.WrapError(
			domain.ErrInternal,
			errors.New("session manager is not initialized"),
		),
		logger,
	)
}
