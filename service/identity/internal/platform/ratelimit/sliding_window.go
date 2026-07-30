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

// slidingWindowScript performs the entire read-modify-write sequence
// atomically inside Redis.
//
// KEYS[1]:
//
//	Rate-limit sorted-set key.
//
// ARGV[1]:
//
//	Current Unix timestamp in milliseconds.
//
// ARGV[2]:
//
//	Sliding-window duration in milliseconds.
//
// ARGV[3]:
//
//	Maximum number of requests permitted in the window.
//
// ARGV[4]:
//
//	Unique event ID, normally the server-generated request ID.
//
// Return values:
//
//	[allowed, remaining, retry_after_milliseconds]
//
// allowed:
//
//	1 when the request is accepted.
//	0 when the limit has been reached.
//
// remaining:
//
//	Number of requests remaining after an accepted request.
//	Always 0 for a rejected request.
//
// retry_after_milliseconds:
//
//	Milliseconds until the oldest event leaves the window.
//	Always 0 for an accepted request.
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

    -- Keep the key bounded even while abusive traffic continues.
    redis.call("PEXPIRE", key, window_ms)

    return {
        0,
        0,
        math.floor(retry_after_ms)
    }
end

-- NX makes the operation idempotent if the same request ID is checked
-- more than once for the same rate-limit key.
redis.call(
    "ZADD",
    key,
    "NX",
    now_ms,
    event_id
)

current_count = redis.call("ZCARD", key)

-- The key expires after a full period without another check. This bounds
-- storage for subjects that stop sending requests.
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

// Allow checks and consumes one request from the given sliding window.
//
// Any returned error means no allow decision could be made safely.
// Sensitive callers must fail closed and reject the request.
//
// eventID must uniquely identify the HTTP request. The request ID produced
// by the HTTP middleware is suitable for this purpose.
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

	// Use Redis as the shared clock so separate application instances do not
	// enforce windows using potentially different host clocks.
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
	if len(key) <= len(rateLimitKeyPrefix) ||
		len(key) > maxKeyLength {
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
	if eventID == "" || len(eventID) > maxEventIDLength {
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

	if remaining < 0 || retryAfterMilliseconds < 0 {
		return Result{}, fmt.Errorf(
			"%w: negative numeric value",
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
