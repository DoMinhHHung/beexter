package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/redis/go-redis/v9"
)

const (
	rateLimitKeyPrefix = "rate_limit:"
	maxKeyLength       = 512
	maxEventIDLength   = 128
)

const slidingWindowScript = `
local key = KEYS[1]

local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local request_limit = tonumber(ARGV[3])
local event_id = ARGV[4]

local cutoff_ms = now_ms - window_ms

redis.call(
    "ZREMRANGEBYSCORE",
    key,
    "-inf",
    cutoff_ms
)

-- A request may reach the limiter more than once because of application
-- retries or duplicate middleware execution.
--
-- The server-generated event ID makes that repeated check idempotent:
-- it returns the current decision without consuming another slot.
local existing_score = redis.call(
    "ZSCORE",
    key,
    event_id
)

if existing_score then
    local current_count = redis.call("ZCARD", key)
    local remaining = request_limit - current_count

    if remaining < 0 then
        remaining = 0
    end

    redis.call("PEXPIRE", key, window_ms)

    return {
        1,
        remaining,
        0
    }
end

local current_count = redis.call("ZCARD", key)

if current_count >= request_limit then
    local oldest = redis.call(
        "ZRANGE",
        key,
        0,
        0,
        "WITHSCORES"
    )

    local retry_after_ms = window_ms

    if #oldest == 2 then
        retry_after_ms =
            tonumber(oldest[2]) +
            window_ms -
            now_ms

        if retry_after_ms < 1 then
            retry_after_ms = 1
        end
    end

    -- Keep the key alive only as long as events in the current window
    -- may still affect a future decision.
    redis.call("PEXPIRE", key, window_ms)

    return {
        0,
        0,
        math.floor(retry_after_ms)
    }
end

redis.call(
    "ZADD",
    key,
    now_ms,
    event_id
)

current_count = current_count + 1

redis.call("PEXPIRE", key, window_ms)

local remaining = request_limit - current_count

if remaining < 0 then
    remaining = 0
end

return {
    1,
    remaining,
    0
}
`

var (
	ErrNotInitialized = errors.New(
		"rate limiter is not initialized",
	)

	ErrInvalidContext = errors.New(
		"rate limiter context is required",
	)

	ErrInvalidKey = errors.New(
		"rate-limit key is invalid",
	)

	ErrInvalidEventID = errors.New(
		"rate-limit event ID is invalid",
	)

	ErrInvalidLimit = errors.New(
		"rate-limit request limit must be greater than zero",
	)

	ErrInvalidWindow = errors.New(
		"rate-limit window must be greater than zero",
	)

	ErrInvalidOperationTimeout = errors.New(
		"rate-limit operation timeout must be greater than zero",
	)

	ErrUnexpectedScriptResult = errors.New(
		"unexpected rate-limit script result",
	)
)

type Result struct {
	Allowed    bool
	Remaining  int64
	RetryAfter time.Duration
}

type SlidingWindow struct {
	client           *redis.Client
	script           *redis.Script
	operationTimeout time.Duration
}

func NewSlidingWindow(
	client *redis.Client,
	operationTimeout time.Duration,
) (*SlidingWindow, error) {
	if client == nil {
		return nil, ErrNotInitialized
	}

	if operationTimeout <= 0 {
		return nil, ErrInvalidOperationTimeout
	}

	return &SlidingWindow{
		client:           client,
		script:           redis.NewScript(slidingWindowScript),
		operationTimeout: operationTimeout,
	}, nil
}

func (l *SlidingWindow) Allow(
	ctx context.Context,
	key string,
	eventID string,
	limit int64,
	window time.Duration,
) (Result, error) {
	if l == nil || l.client == nil || l.script == nil {
		return Result{}, ErrNotInitialized
	}

	if ctx == nil {
		return Result{}, ErrInvalidContext
	}

	if err := validateKey(key); err != nil {
		return Result{}, err
	}

	if err := validateEventID(eventID); err != nil {
		return Result{}, err
	}

	if limit <= 0 {
		return Result{}, ErrInvalidLimit
	}

	windowMilliseconds := window.Milliseconds()
	if window <= 0 || windowMilliseconds <= 0 {
		return Result{}, ErrInvalidWindow
	}

	operationContext, cancel := context.WithTimeout(
		ctx,
		l.operationTimeout,
	)
	defer cancel()

	now, err := l.client.Time(operationContext).Result()
	if err != nil {
		return Result{}, fmt.Errorf(
			"read Redis server time: %w",
			err,
		)
	}

	rawResult, err := l.script.Run(
		operationContext,
		l.client,
		[]string{key},
		now.UnixMilli(),
		windowMilliseconds,
		limit,
		eventID,
	).Slice()
	if err != nil {
		return Result{}, fmt.Errorf(
			"execute sliding-window rate-limit script: %w",
			err,
		)
	}

	result, err := parseScriptResult(rawResult)
	if err != nil {
		return Result{}, err
	}

	return result, nil
}

func validateKey(key string) error {
	if len(key) <= len(rateLimitKeyPrefix) {
		return ErrInvalidKey
	}

	if len(key) > maxKeyLength {
		return ErrInvalidKey
	}

	if !strings.HasPrefix(key, rateLimitKeyPrefix) {
		return ErrInvalidKey
	}

	if strings.IndexFunc(key, unicode.IsSpace) >= 0 {
		return ErrInvalidKey
	}

	return nil
}

func validateEventID(eventID string) error {
	if eventID == "" {
		return ErrInvalidEventID
	}

	if len(eventID) > maxEventIDLength {
		return ErrInvalidEventID
	}

	if strings.IndexFunc(eventID, unicode.IsSpace) >= 0 {
		return ErrInvalidEventID
	}

	return nil
}

func parseScriptResult(rawResult []any) (Result, error) {
	if len(rawResult) != 3 {
		return Result{}, fmt.Errorf(
			"%w: expected 3 values, received %d",
			ErrUnexpectedScriptResult,
			len(rawResult),
		)
	}

	allowedValue, err := parseScriptInteger(rawResult[0])
	if err != nil {
		return Result{}, fmt.Errorf(
			"%w: parse allowed value: %v",
			ErrUnexpectedScriptResult,
			err,
		)
	}

	remaining, err := parseScriptInteger(rawResult[1])
	if err != nil {
		return Result{}, fmt.Errorf(
			"%w: parse remaining value: %v",
			ErrUnexpectedScriptResult,
			err,
		)
	}

	retryAfterMilliseconds, err := parseScriptInteger(
		rawResult[2],
	)
	if err != nil {
		return Result{}, fmt.Errorf(
			"%w: parse retry-after value: %v",
			ErrUnexpectedScriptResult,
			err,
		)
	}

	if allowedValue != 0 && allowedValue != 1 {
		return Result{}, fmt.Errorf(
			"%w: allowed value must be 0 or 1",
			ErrUnexpectedScriptResult,
		)
	}

	if remaining < 0 {
		return Result{}, fmt.Errorf(
			"%w: remaining value is negative",
			ErrUnexpectedScriptResult,
		)
	}

	if retryAfterMilliseconds < 0 {
		return Result{}, fmt.Errorf(
			"%w: retry-after value is negative",
			ErrUnexpectedScriptResult,
		)
	}

	result := Result{
		Allowed:   allowedValue == 1,
		Remaining: remaining,
	}

	if retryAfterMilliseconds > 0 {
		result.RetryAfter =
			time.Duration(retryAfterMilliseconds) *
				time.Millisecond
	}

	if result.Allowed && result.RetryAfter != 0 {
		return Result{}, fmt.Errorf(
			"%w: allowed result has retry-after duration",
			ErrUnexpectedScriptResult,
		)
	}

	if !result.Allowed && result.Remaining != 0 {
		return Result{}, fmt.Errorf(
			"%w: rejected result has remaining capacity",
			ErrUnexpectedScriptResult,
		)
	}

	return result, nil
}

func parseScriptInteger(value any) (int64, error) {
	switch typedValue := value.(type) {
	case int64:
		return typedValue, nil

	case int:
		return int64(typedValue), nil

	case string:
		parsed, err := strconv.ParseInt(
			typedValue,
			10,
			64,
		)
		if err != nil {
			return 0, fmt.Errorf(
				"parse string integer: %w",
				err,
			)
		}

		return parsed, nil

	case []byte:
		parsed, err := strconv.ParseInt(
			string(typedValue),
			10,
			64,
		)
		if err != nil {
			return 0, fmt.Errorf(
				"parse byte integer: %w",
				err,
			)
		}

		return parsed, nil

	default:
		return 0, fmt.Errorf(
			"unsupported value type %T",
			value,
		)
	}
}
