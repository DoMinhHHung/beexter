package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix           = "refresh_token:"
	indexKeyPrefix      = "refresh_token_index:"
	revocationKeyPrefix = "refresh_token_revoked_before:"
	refreshTokenTTL     = 604800 * time.Second
)

const saveSessionScript = `
local revoked_before = redis.call("GET", KEYS[3])
if revoked_before and ARGV[3] <= revoked_before then
    return 0
end

redis.call("SET", KEYS[1], ARGV[1], "PX", ARGV[2])
redis.call("SADD", KEYS[2], KEYS[1])
redis.call("PEXPIRE", KEYS[2], ARGV[2])
return 1
`

const deleteSessionScript = `
local deleted = redis.call("DEL", KEYS[1])
redis.call("SREM", KEYS[2], KEYS[1])
if redis.call("SCARD", KEYS[2]) == 0 then
    redis.call("DEL", KEYS[2])
end
return deleted
`

const listSessionsScript = `
local session_keys = redis.call("SMEMBERS", KEYS[1])
local revoked_before = redis.call("GET", KEYS[2])
local sessions = {}

for _, session_key in ipairs(session_keys) do
    local raw_session = redis.call("GET", session_key)
    if not raw_session then
        redis.call("SREM", KEYS[1], session_key)
    elseif revoked_before then
        local decoded_ok, current = pcall(cjson.decode, raw_session)
        if decoded_ok
            and type(current) == "table"
            and type(current.created_at) == "string"
            and current.created_at <= revoked_before then
            redis.call("DEL", session_key)
            redis.call("SREM", KEYS[1], session_key)
        else
            table.insert(sessions, raw_session)
        end
    else
        table.insert(sessions, raw_session)
    end
end

if redis.call("SCARD", KEYS[1]) == 0 then
    redis.call("DEL", KEYS[1])
end

return sessions
`

const rotateSessionScript = `
local function revoke_all()
    redis.call("DEL", KEYS[1])
    local session_keys = redis.call("SMEMBERS", KEYS[2])
    for _, session_key in ipairs(session_keys) do
        redis.call("DEL", session_key)
    end
    redis.call("DEL", KEYS[2])
end

local raw_session = redis.call("GET", KEYS[1])
if not raw_session then
    revoke_all()
    return 0
end

local decoded_ok, current = pcall(cjson.decode, raw_session)
if not decoded_ok or type(current) ~= "table" then
    revoke_all()
    return -2
end

if current.token ~= ARGV[1]
    or current.user_id ~= ARGV[2]
    or current.device_id ~= ARGV[3] then
    revoke_all()
    return -1
end

local revoked_before = redis.call("GET", KEYS[3])
if revoked_before then
    if type(current.created_at) ~= "string" then
        revoke_all()
        return -2
    end
    if current.created_at <= revoked_before then
        revoke_all()
        return 0
    end
end

current.token = ARGV[4]
current.user_agent = ARGV[5]
current.ip_address = ARGV[6]
current.expires_at = ARGV[7]
current.last_used_at = ARGV[8]

redis.call(
    "SET",
    KEYS[1],
    cjson.encode(current),
    "PX",
    ARGV[9]
)
redis.call("SADD", KEYS[2], KEYS[1])
redis.call("PEXPIRE", KEYS[2], ARGV[9])
return 1
`

const revokeAllSessionsScript = `
local session_keys = redis.call("SMEMBERS", KEYS[1])
local deleted = 0
for _, session_key in ipairs(session_keys) do
    deleted = deleted + redis.call("DEL", session_key)
end
redis.call("DEL", KEYS[1])
return deleted
`

const revokeSessionsCreatedAtOrBeforeScript = `
local existing_cutoff = redis.call("GET", KEYS[2])
if not existing_cutoff or existing_cutoff < ARGV[2] then
    redis.call("SET", KEYS[2], ARGV[2], "PX", ARGV[3])
else
    redis.call("PEXPIRE", KEYS[2], ARGV[3])
end

local session_keys = redis.call("SMEMBERS", KEYS[1])
local deleted = 0

for _, session_key in ipairs(session_keys) do
    local raw_session = redis.call("GET", session_key)
    if not raw_session then
        redis.call("SREM", KEYS[1], session_key)
    else
        local decoded_ok, current = pcall(cjson.decode, raw_session)
        if not decoded_ok or type(current) ~= "table" then
            deleted = deleted + redis.call("DEL", session_key)
            redis.call("SREM", KEYS[1], session_key)
        elseif current.user_id ~= ARGV[1] then
            redis.call("SREM", KEYS[1], session_key)
        elseif type(current.created_at) ~= "string" then
            deleted = deleted + redis.call("DEL", session_key)
            redis.call("SREM", KEYS[1], session_key)
        elseif current.created_at <= ARGV[2] then
            deleted = deleted + redis.call("DEL", session_key)
            redis.call("SREM", KEYS[1], session_key)
        end
    end
end

if redis.call("SCARD", KEYS[1]) == 0 then
    redis.call("DEL", KEYS[1])
end

return deleted
`

var (
	ErrNotInitialized          = errors.New("session store is not initialized")
	ErrInvalidContext          = errors.New("session context is required")
	ErrInvalidOperationTimeout = errors.New(
		"session operation timeout must be greater than zero",
	)
	ErrInvalidSession = errors.New("refresh session is invalid")
	ErrCorruptSession = errors.New("refresh session state is corrupt")
	ErrSessionRevoked = errors.New(
		"refresh session was rejected by a credential revocation fence",
	)
)

type Store struct {
	client             *redis.Client
	operationTimeout   time.Duration
	saveScript         *redis.Script
	deleteScript       *redis.Script
	listScript         *redis.Script
	rotateScript       *redis.Script
	revokeAllScript    *redis.Script
	revokeBeforeScript *redis.Script
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
		client:             client,
		operationTimeout:   operationTimeout,
		saveScript:         redis.NewScript(saveSessionScript),
		deleteScript:       redis.NewScript(deleteSessionScript),
		listScript:         redis.NewScript(listSessionsScript),
		rotateScript:       redis.NewScript(rotateSessionScript),
		revokeAllScript:    redis.NewScript(revokeAllSessionsScript),
		revokeBeforeScript: redis.NewScript(revokeSessionsCreatedAtOrBeforeScript),
	}, nil
}

func (s *Store) Save(
	ctx context.Context,
	session appauth.Session,
) error {
	if err := s.validate(ctx); err != nil {
		return err
	}

	if err := validateSession(session); err != nil {
		return err
	}

	payload, err := marshalSession(session)
	if err != nil {
		return err
	}

	operationContext, cancelOperation := context.WithTimeout(
		ctx,
		s.operationTimeout,
	)
	defer cancelOperation()

	result, err := s.saveScript.Run(
		operationContext,
		s.client,
		[]string{
			key(session.UserID, session.DeviceID),
			indexKey(session.UserID),
			revocationKey(session.UserID),
		},
		payload,
		refreshTokenTTL.Milliseconds(),
		session.CreatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	).Int64()
	if err != nil {
		return fmt.Errorf("save refresh session in Redis: %w", err)
	}
	if result == 0 {
		return ErrSessionRevoked
	}
	if result != 1 {
		return fmt.Errorf(
			"%w: unexpected save result %d",
			ErrCorruptSession,
			result,
		)
	}

	return nil
}

func (s *Store) Delete(
	ctx context.Context,
	userID identity.ID,
	deviceID string,
) error {
	if err := s.validate(ctx); err != nil {
		return err
	}

	if userID.IsZero() || validateCanonicalUUIDV7(deviceID) != nil {
		return ErrInvalidSession
	}

	operationContext, cancelOperation := context.WithTimeout(
		ctx,
		s.operationTimeout,
	)
	defer cancelOperation()

	if _, err := s.deleteScript.Run(
		operationContext,
		s.client,
		[]string{
			key(userID, deviceID),
			indexKey(userID),
		},
	).Result(); err != nil {
		return fmt.Errorf("delete refresh session from Redis: %w", err)
	}

	return nil
}

func (s *Store) List(
	ctx context.Context,
	userID identity.ID,
) ([]appauth.Session, error) {
	if err := s.validate(ctx); err != nil {
		return nil, err
	}

	if userID.IsZero() {
		return nil, ErrInvalidSession
	}

	operationContext, cancelOperation := context.WithTimeout(
		ctx,
		s.operationTimeout,
	)
	defer cancelOperation()

	rawSessions, err := s.listScript.Run(
		operationContext,
		s.client,
		[]string{
			indexKey(userID),
			revocationKey(userID),
		},
	).StringSlice()
	if err != nil {
		return nil, fmt.Errorf("list refresh sessions from Redis: %w", err)
	}

	sessions := make([]appauth.Session, 0, len(rawSessions))
	for _, rawSession := range rawSessions {
		session, err := unmarshalSession(rawSession)
		if err != nil {
			return nil, err
		}

		if session.UserID != userID {
			return nil, fmt.Errorf(
				"%w: session identity does not match index",
				ErrCorruptSession,
			)
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (s *Store) Rotate(
	ctx context.Context,
	rotation appauth.Rotation,
) error {
	if err := s.validate(ctx); err != nil {
		return err
	}

	if err := validateRotation(rotation); err != nil {
		return err
	}

	operationContext, cancelOperation := context.WithTimeout(
		ctx,
		s.operationTimeout,
	)
	defer cancelOperation()

	result, err := s.rotateScript.Run(
		operationContext,
		s.client,
		[]string{
			key(rotation.UserID, rotation.DeviceID),
			indexKey(rotation.UserID),
			revocationKey(rotation.UserID),
		},
		rotation.PresentedTokenID,
		rotation.UserID.String(),
		rotation.DeviceID,
		rotation.ReplacementTokenID,
		rotation.UserAgent,
		rotation.IPAddress.Unmap().String(),
		rotation.ExpiresAt.UTC().Format(time.RFC3339),
		rotation.LastUsedAt.UTC().Format(time.RFC3339),
		refreshTokenTTL.Milliseconds(),
	).Int64()
	if err != nil {
		return fmt.Errorf("rotate refresh session in Redis: %w", err)
	}

	switch result {
	case 1:
		return nil

	case 0, -1:
		return appauth.ErrRefreshTokenReuse

	case -2:
		return ErrCorruptSession

	default:
		return fmt.Errorf(
			"%w: unexpected rotation result %d",
			ErrCorruptSession,
			result,
		)
	}
}

func (s *Store) RevokeAll(
	ctx context.Context,
	userID identity.ID,
) error {
	if err := s.validate(ctx); err != nil {
		return err
	}

	if userID.IsZero() {
		return ErrInvalidSession
	}

	operationContext, cancelOperation := context.WithTimeout(
		ctx,
		s.operationTimeout,
	)
	defer cancelOperation()

	if _, err := s.revokeAllScript.Run(
		operationContext,
		s.client,
		[]string{indexKey(userID)},
	).Result(); err != nil {
		return fmt.Errorf("revoke all refresh sessions in Redis: %w", err)
	}

	return nil
}

func (s *Store) RevokeCreatedAtOrBefore(
	ctx context.Context,
	userID identity.ID,
	cutoff time.Time,
) error {
	if err := s.validate(ctx); err != nil {
		return err
	}

	if userID.IsZero() || cutoff.IsZero() {
		return ErrInvalidSession
	}

	operationContext, cancelOperation := context.WithTimeout(
		ctx,
		s.operationTimeout,
	)
	defer cancelOperation()

	if _, err := s.revokeBeforeScript.Run(
		operationContext,
		s.client,
		[]string{
			indexKey(userID),
			revocationKey(userID),
		},
		userID.String(),
		cutoff.UTC().Truncate(time.Second).Format(time.RFC3339),
		refreshTokenTTL.Milliseconds(),
	).Result(); err != nil {
		return fmt.Errorf(
			"revoke refresh sessions created at or before cutoff in Redis: %w",
			err,
		)
	}

	return nil
}

func (s *Store) validate(ctx context.Context) error {
	if s == nil ||
		s.client == nil ||
		s.saveScript == nil ||
		s.deleteScript == nil ||
		s.listScript == nil ||
		s.rotateScript == nil ||
		s.revokeAllScript == nil ||
		s.revokeBeforeScript == nil {
		return ErrNotInitialized
	}

	if ctx == nil {
		return ErrInvalidContext
	}

	return nil
}

func marshalSession(session appauth.Session) ([]byte, error) {
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
		return nil, fmt.Errorf("marshal refresh session: %w", err)
	}

	return payload, nil
}

func unmarshalSession(rawSession string) (appauth.Session, error) {
	decoder := json.NewDecoder(bytes.NewBufferString(rawSession))
	decoder.DisallowUnknownFields()

	var payload redisPayload
	if err := decoder.Decode(&payload); err != nil {
		return appauth.Session{}, fmt.Errorf(
			"%w: decode session payload: %v",
			ErrCorruptSession,
			err,
		)
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return appauth.Session{}, fmt.Errorf(
				"%w: multiple JSON values",
				ErrCorruptSession,
			)
		}

		return appauth.Session{}, fmt.Errorf(
			"%w: decode trailing session data: %v",
			ErrCorruptSession,
			err,
		)
	}

	userID, err := identity.ParseID(payload.UserID)
	if err != nil {
		return appauth.Session{}, fmt.Errorf(
			"%w: parse user ID: %v",
			ErrCorruptSession,
			err,
		)
	}

	ipAddress, err := netip.ParseAddr(payload.IPAddress)
	if err != nil {
		return appauth.Session{}, fmt.Errorf(
			"%w: parse IP address: %v",
			ErrCorruptSession,
			err,
		)
	}

	createdAt, err := time.Parse(time.RFC3339, payload.CreatedAt)
	if err != nil {
		return appauth.Session{}, fmt.Errorf(
			"%w: parse created_at: %v",
			ErrCorruptSession,
			err,
		)
	}

	expiresAt, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil {
		return appauth.Session{}, fmt.Errorf(
			"%w: parse expires_at: %v",
			ErrCorruptSession,
			err,
		)
	}

	lastUsedAt, err := time.Parse(time.RFC3339, payload.LastUsedAt)
	if err != nil {
		return appauth.Session{}, fmt.Errorf(
			"%w: parse last_used_at: %v",
			ErrCorruptSession,
			err,
		)
	}

	session := appauth.Session{
		Token:      payload.Token,
		UserID:     userID,
		DeviceID:   payload.DeviceID,
		UserAgent:  payload.UserAgent,
		IPAddress:  ipAddress.Unmap(),
		CreatedAt:  createdAt.UTC(),
		ExpiresAt:  expiresAt.UTC(),
		LastUsedAt: lastUsedAt.UTC(),
	}

	if err := validateSession(session); err != nil {
		return appauth.Session{}, fmt.Errorf(
			"%w: %v",
			ErrCorruptSession,
			err,
		)
	}

	return session, nil
}

func validateSession(session appauth.Session) error {
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

	if validateCanonicalUUIDV7(session.Token) != nil ||
		validateCanonicalUUIDV7(session.DeviceID) != nil {
		return ErrInvalidSession
	}

	createdAt := session.CreatedAt.UTC().Truncate(time.Second)
	expiresAt := session.ExpiresAt.UTC().Truncate(time.Second)
	lastUsedAt := session.LastUsedAt.UTC().Truncate(time.Second)

	if lastUsedAt.Before(createdAt) ||
		!expiresAt.Equal(lastUsedAt.Add(refreshTokenTTL)) {
		return ErrInvalidSession
	}

	return nil
}

func validateRotation(rotation appauth.Rotation) error {
	if rotation.UserID.IsZero() ||
		strings.TrimSpace(rotation.UserAgent) == "" ||
		!rotation.IPAddress.IsValid() ||
		rotation.ExpiresAt.IsZero() ||
		rotation.LastUsedAt.IsZero() ||
		validateCanonicalUUIDV7(rotation.DeviceID) != nil ||
		validateCanonicalUUIDV7(rotation.PresentedTokenID) != nil ||
		validateCanonicalUUIDV7(rotation.ReplacementTokenID) != nil {
		return ErrInvalidSession
	}

	lastUsedAt := rotation.LastUsedAt.UTC().Truncate(time.Second)
	expiresAt := rotation.ExpiresAt.UTC().Truncate(time.Second)
	if !expiresAt.Equal(lastUsedAt.Add(refreshTokenTTL)) {
		return ErrInvalidSession
	}

	return nil
}

func key(userID identity.ID, deviceID string) string {
	return keyPrefix + userID.String() + ":" + deviceID
}

func indexKey(userID identity.ID) string {
	return indexKeyPrefix + userID.String()
}

func revocationKey(userID identity.ID) string {
	return revocationKeyPrefix + userID.String()
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
