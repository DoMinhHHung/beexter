package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	applogin "github.com/DoMinhHHung/beexter/service/identity/internal/application/login"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix       = "refresh_token:"
	refreshTokenTTL = 604800 * time.Second
)

var (
	ErrNotInitialized          = errors.New("session store is not initialized")
	ErrInvalidContext          = errors.New("session context is required")
	ErrInvalidOperationTimeout = errors.New("session operation timeout must be greater than zero")
	ErrInvalidSession          = errors.New("refresh session is invalid")
)

type Store struct {
	client           *redis.Client
	operationTimeout time.Duration
}

type redisPayload struct {
	Token      string `json:"token"`
	UserID     string `json:"user_id"`
	DeviceID   string `json:"device_id"`
	UserAgent  string `json:"user_agent"`
	IPAddress  string `json:"ip_address"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
	LastUsedAt string `json:"last_used_at"`
}

func NewStore(
	client *redis.Client,
	operationTimeout time.Duration,
) (*Store, error) {
	if client == nil {
		return nil, ErrNotInitialized
	}

	if operationTimeout <= 0 {
		return nil, ErrInvalidOperationTimeout
	}

	return &Store{
		client:           client,
		operationTimeout: operationTimeout,
	}, nil
}

func (s *Store) Save(
	ctx context.Context,
	session applogin.Session,
) error {
	if s == nil || s.client == nil {
		return ErrNotInitialized
	}

	if ctx == nil {
		return ErrInvalidContext
	}

	if err := validateSession(session); err != nil {
		return err
	}

	payload, err := json.Marshal(redisPayload{
		Token:      session.Token,
		UserID:     session.UserID.String(),
		DeviceID:   session.DeviceID,
		UserAgent:  session.UserAgent,
		IPAddress:  session.IPAddress.Unmap().String(),
		CreatedAt:  session.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt:  session.ExpiresAt.UTC().Format(time.RFC3339),
		LastUsedAt: session.LastUsedAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("marshal refresh session: %w", err)
	}

	operationContext, cancelOperation := context.WithTimeout(
		ctx,
		s.operationTimeout,
	)
	defer cancelOperation()

	if err := s.client.Set(
		operationContext,
		key(session.UserID, session.DeviceID),
		payload,
		refreshTokenTTL,
	).Err(); err != nil {
		return fmt.Errorf("save refresh session in Redis: %w", err)
	}

	return nil
}

func (s *Store) Delete(
	ctx context.Context,
	userID identity.ID,
	deviceID string,
) error {
	if s == nil || s.client == nil {
		return ErrNotInitialized
	}

	if ctx == nil {
		return ErrInvalidContext
	}

	if userID.IsZero() || validateCanonicalUUIDV7(deviceID) != nil {
		return ErrInvalidSession
	}

	operationContext, cancelOperation := context.WithTimeout(
		ctx,
		s.operationTimeout,
	)
	defer cancelOperation()

	if err := s.client.Del(
		operationContext,
		key(userID, deviceID),
	).Err(); err != nil {
		return fmt.Errorf("delete refresh session from Redis: %w", err)
	}

	return nil
}

func validateSession(session applogin.Session) error {
	if session.UserID.IsZero() ||
		session.Token == "" ||
		session.DeviceID == "" ||
		strings.TrimSpace(session.UserAgent) == "" ||
		!session.IPAddress.IsValid() ||
		session.CreatedAt.IsZero() ||
		session.ExpiresAt.IsZero() ||
		session.LastUsedAt.IsZero() {
		return ErrInvalidSession
	}

	if err := validateCanonicalUUIDV7(session.Token); err != nil {
		return ErrInvalidSession
	}

	if err := validateCanonicalUUIDV7(session.DeviceID); err != nil {
		return ErrInvalidSession
	}

	createdAt := session.CreatedAt.UTC().Truncate(time.Second)
	expiresAt := session.ExpiresAt.UTC().Truncate(time.Second)
	lastUsedAt := session.LastUsedAt.UTC().Truncate(time.Second)

	if !expiresAt.Equal(createdAt.Add(refreshTokenTTL)) ||
		lastUsedAt.Before(createdAt) ||
		lastUsedAt.After(expiresAt) {
		return ErrInvalidSession
	}

	return nil
}

func key(userID identity.ID, deviceID string) string {
	return fmt.Sprintf(
		"%s%s:%s",
		keyPrefix,
		userID.String(),
		deviceID,
	)
}

func validateCanonicalUUIDV7(rawID string) error {
	parsedID, err := uuid.Parse(rawID)
	if err != nil {
		return err
	}

	if parsedID.Version() != 7 ||
		parsedID.Variant() != uuid.RFC4122 ||
		parsedID.String() != rawID {
		return errors.New("ID must be a canonical UUID v7")
	}

	return nil
}

var _ applogin.SessionStore = (*Store)(nil)
