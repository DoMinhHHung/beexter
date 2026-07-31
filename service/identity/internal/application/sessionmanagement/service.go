package sessionmanagement

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

var ErrDependencyMissing = errors.New(
	"session-management dependency is missing",
)

type Session struct {
	DeviceID   string
	UserAgent  string
	IPAddress  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
	Current    bool
}

type Store interface {
	Delete(
		ctx context.Context,
		userID identity.ID,
		deviceID string,
	) error

	RevokeAll(
		ctx context.Context,
		userID identity.ID,
	) error

	List(
		ctx context.Context,
		userID identity.ID,
	) ([]appauth.Session, error)
}

type Service struct {
	store Store
}

func New(store Store) (*Service, error) {
	if store == nil {
		return nil, ErrDependencyMissing
	}

	return &Service{store: store}, nil
}

func (s *Service) LogoutCurrent(
	ctx context.Context,
	principal appauth.Principal,
) error {
	if err := s.validate(ctx, principal); err != nil {
		return err
	}

	if err := s.store.Delete(
		ctx,
		principal.UserID,
		principal.DeviceID,
	); err != nil {
		return domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("delete current refresh session: %w", err),
		)
	}

	return nil
}

func (s *Service) LogoutAll(
	ctx context.Context,
	principal appauth.Principal,
) error {
	if err := s.validate(ctx, principal); err != nil {
		return err
	}

	if err := s.store.RevokeAll(ctx, principal.UserID); err != nil {
		return domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("revoke all refresh sessions: %w", err),
		)
	}

	return nil
}

func (s *Service) List(
	ctx context.Context,
	principal appauth.Principal,
) ([]Session, error) {
	if err := s.validate(ctx, principal); err != nil {
		return nil, err
	}

	storedSessions, err := s.store.List(ctx, principal.UserID)
	if err != nil {
		return nil, domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("list refresh sessions: %w", err),
		)
	}

	sessions := make([]Session, 0, len(storedSessions))
	for _, storedSession := range storedSessions {
		if storedSession.UserID != principal.UserID {
			return nil, domain.WrapError(
				domain.ErrInternal,
				errors.New("session store returned a foreign identity"),
			)
		}

		sessions = append(sessions, Session{
			DeviceID:   storedSession.DeviceID,
			UserAgent:  storedSession.UserAgent,
			IPAddress:  storedSession.IPAddress.Unmap().String(),
			CreatedAt:  storedSession.CreatedAt,
			ExpiresAt:  storedSession.ExpiresAt,
			LastUsedAt: storedSession.LastUsedAt,
			Current:    storedSession.DeviceID == principal.DeviceID,
		})
	}

	sort.SliceStable(sessions, func(i, j int) bool {
		if sessions[i].LastUsedAt.Equal(sessions[j].LastUsedAt) {
			return sessions[i].DeviceID < sessions[j].DeviceID
		}

		return sessions[i].LastUsedAt.After(sessions[j].LastUsedAt)
	})

	return sessions, nil
}

func (s *Service) Revoke(
	ctx context.Context,
	principal appauth.Principal,
	deviceID string,
) error {
	if err := s.validate(ctx, principal); err != nil {
		return err
	}

	if _, err := identity.ParseID(deviceID); err != nil {
		return domain.WrapError(
			domain.ErrInvalidInput,
			fmt.Errorf("validate device ID: %w", err),
		)
	}

	if err := s.store.Delete(
		ctx,
		principal.UserID,
		deviceID,
	); err != nil {
		return domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("revoke refresh session: %w", err),
		)
	}

	return nil
}

func (s *Service) validate(
	ctx context.Context,
	principal appauth.Principal,
) error {
	if s == nil || s.store == nil {
		return domain.WrapError(
			domain.ErrInternal,
			ErrDependencyMissing,
		)
	}

	if ctx == nil {
		return domain.WrapError(
			domain.ErrInternal,
			errors.New("session-management context is required"),
		)
	}

	if principal.UserID.IsZero() ||
		!principal.PlatformRole.IsValidOrEmpty() {
		return domain.NewError(domain.ErrForbidden)
	}

	if _, err := identity.ParseID(principal.DeviceID); err != nil {
		return domain.WrapError(
			domain.ErrInternal,
			fmt.Errorf("validate authenticated device ID: %w", err),
		)
	}

	return nil
}
