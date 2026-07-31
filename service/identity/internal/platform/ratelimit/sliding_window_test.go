package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const testOperationTimeout = 500 * time.Millisecond

func TestSlidingWindowAllowsUntilLimit(t *testing.T) {
	t.Parallel()

	_, client, limiter := newTestLimiter(t)

	const (
		key    = "rate_limit:login:ip:192.0.2.1"
		limit  = int64(2)
		window = time.Minute
	)

	firstResult, err := limiter.Allow(
		context.Background(),
		key,
		"request-1",
		limit,
		window,
	)
	if err != nil {
		t.Fatalf("allow first request: %v", err)
	}

	if !firstResult.Allowed {
		t.Fatal("expected first request to be allowed")
	}

	if firstResult.Remaining != 1 {
		t.Fatalf(
			"expected 1 remaining request, got %d",
			firstResult.Remaining,
		)
	}

	secondResult, err := limiter.Allow(
		context.Background(),
		key,
		"request-2",
		limit,
		window,
	)
	if err != nil {
		t.Fatalf("allow second request: %v", err)
	}

	if !secondResult.Allowed {
		t.Fatal("expected second request to be allowed")
	}

	if secondResult.Remaining != 0 {
		t.Fatalf(
			"expected 0 remaining requests, got %d",
			secondResult.Remaining,
		)
	}

	rejectedResult, err := limiter.Allow(
		context.Background(),
		key,
		"request-3",
		limit,
		window,
	)
	if err != nil {
		t.Fatalf("check rejected request: %v", err)
	}

	if rejectedResult.Allowed {
		t.Fatal("expected third request to be rejected")
	}

	if rejectedResult.Remaining != 0 {
		t.Fatalf(
			"expected 0 remaining requests, got %d",
			rejectedResult.Remaining,
		)
	}

	if rejectedResult.RetryAfter <= 0 {
		t.Fatal("expected positive retry-after duration")
	}

	if rejectedResult.RetryAfter > window {
		t.Fatalf(
			"retry-after must not exceed window: %s",
			rejectedResult.RetryAfter,
		)
	}

	ttl, err := client.PTTL(
		context.Background(),
		key,
	).Result()
	if err != nil {
		t.Fatalf("read rate-limit key TTL: %v", err)
	}

	if ttl <= 0 {
		t.Fatalf("expected positive key TTL, got %s", ttl)
	}

	if ttl > window {
		t.Fatalf(
			"expected TTL no greater than %s, got %s",
			window,
			ttl,
		)
	}
}

func TestSlidingWindowDuplicateEventIsIdempotent(t *testing.T) {
	t.Parallel()

	_, _, limiter := newTestLimiter(t)

	const (
		key    = "rate_limit:signup:ip:192.0.2.2"
		limit  = int64(2)
		window = time.Minute
	)

	firstResult, err := limiter.Allow(
		context.Background(),
		key,
		"request-1",
		limit,
		window,
	)
	if err != nil {
		t.Fatalf("allow first request: %v", err)
	}

	duplicateResult, err := limiter.Allow(
		context.Background(),
		key,
		"request-1",
		limit,
		window,
	)
	if err != nil {
		t.Fatalf("allow duplicate request: %v", err)
	}

	if !duplicateResult.Allowed {
		t.Fatal("expected duplicate event to remain allowed")
	}

	if duplicateResult.Remaining != firstResult.Remaining {
		t.Fatalf(
			"duplicate request consumed capacity: before=%d after=%d",
			firstResult.Remaining,
			duplicateResult.Remaining,
		)
	}

	secondResult, err := limiter.Allow(
		context.Background(),
		key,
		"request-2",
		limit,
		window,
	)
	if err != nil {
		t.Fatalf("allow second unique request: %v", err)
	}

	if !secondResult.Allowed {
		t.Fatal("expected second unique request to be allowed")
	}

	rejectedResult, err := limiter.Allow(
		context.Background(),
		key,
		"request-3",
		limit,
		window,
	)
	if err != nil {
		t.Fatalf("check third unique request: %v", err)
	}

	if rejectedResult.Allowed {
		t.Fatal("expected third unique request to be rejected")
	}
}

func TestSlidingWindowAllowsAfterWindowExpires(t *testing.T) {
	t.Parallel()

	server, _, limiter := newTestLimiter(t)

	const (
		key    = "rate_limit:login:email:subject-hash"
		limit  = int64(1)
		window = time.Minute
	)

	firstResult, err := limiter.Allow(
		context.Background(),
		key,
		"request-1",
		limit,
		window,
	)
	if err != nil {
		t.Fatalf("allow first request: %v", err)
	}

	if !firstResult.Allowed {
		t.Fatal("expected first request to be allowed")
	}

	rejectedResult, err := limiter.Allow(
		context.Background(),
		key,
		"request-2",
		limit,
		window,
	)
	if err != nil {
		t.Fatalf("check second request: %v", err)
	}

	if rejectedResult.Allowed {
		t.Fatal("expected second request to be rejected")
	}

	server.FastForward(window + time.Millisecond)

	allowedResult, err := limiter.Allow(
		context.Background(),
		key,
		"request-3",
		limit,
		window,
	)
	if err != nil {
		t.Fatalf("allow request after window: %v", err)
	}

	if !allowedResult.Allowed {
		t.Fatal("expected request after window to be allowed")
	}

	if allowedResult.Remaining != 0 {
		t.Fatalf(
			"expected 0 remaining requests, got %d",
			allowedResult.Remaining,
		)
	}
}

func TestSlidingWindowFailsClosedWhenRedisIsUnavailable(
	t *testing.T,
) {
	t.Parallel()

	server, _, limiter := newTestLimiter(t)

	server.Close()

	result, err := limiter.Allow(
		context.Background(),
		"rate_limit:login:ip:192.0.2.3",
		"request-1",
		5,
		time.Minute,
	)

	if err == nil {
		t.Fatal("expected Redis connection error")
	}

	if result.Allowed {
		t.Fatal("Redis failure must not return an allowed result")
	}

	if result.Remaining != 0 {
		t.Fatalf(
			"expected zero remaining capacity, got %d",
			result.Remaining,
		)
	}

	if result.RetryAfter != 0 {
		t.Fatalf(
			"expected zero retry-after duration, got %s",
			result.RetryAfter,
		)
	}
}

func TestSlidingWindowRespectsCanceledContext(t *testing.T) {
	t.Parallel()

	_, _, limiter := newTestLimiter(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := limiter.Allow(
		ctx,
		"rate_limit:login:ip:192.0.2.4",
		"request-1",
		5,
		time.Minute,
	)

	if err == nil {
		t.Fatal("expected context cancellation error")
	}

	if result.Allowed {
		t.Fatal("canceled context must not allow request")
	}
}

func TestSlidingWindowValidatesInput(t *testing.T) {
	t.Parallel()

	_, _, limiter := newTestLimiter(t)

	tests := []struct {
		name          string
		ctx           context.Context
		key           string
		eventID       string
		limit         int64
		window        time.Duration
		expectedError error
	}{
		{
			name:          "nil context",
			ctx:           nil,
			key:           "rate_limit:login:ip:192.0.2.1",
			eventID:       "request-1",
			limit:         5,
			window:        time.Minute,
			expectedError: ErrInvalidContext,
		},
		{
			name:          "wrong key namespace",
			ctx:           context.Background(),
			key:           "refresh_token:user:device",
			eventID:       "request-1",
			limit:         5,
			window:        time.Minute,
			expectedError: ErrInvalidKey,
		},
		{
			name:          "empty key subject",
			ctx:           context.Background(),
			key:           "rate_limit:",
			eventID:       "request-1",
			limit:         5,
			window:        time.Minute,
			expectedError: ErrInvalidKey,
		},
		{
			name:          "event ID contains whitespace",
			ctx:           context.Background(),
			key:           "rate_limit:login:ip:192.0.2.1",
			eventID:       "request 1",
			limit:         5,
			window:        time.Minute,
			expectedError: ErrInvalidEventID,
		},
		{
			name:          "zero limit",
			ctx:           context.Background(),
			key:           "rate_limit:login:ip:192.0.2.1",
			eventID:       "request-1",
			limit:         0,
			window:        time.Minute,
			expectedError: ErrInvalidLimit,
		},
		{
			name:          "negative limit",
			ctx:           context.Background(),
			key:           "rate_limit:login:ip:192.0.2.1",
			eventID:       "request-1",
			limit:         -1,
			window:        time.Minute,
			expectedError: ErrInvalidLimit,
		},
		{
			name:          "zero window",
			ctx:           context.Background(),
			key:           "rate_limit:login:ip:192.0.2.1",
			eventID:       "request-1",
			limit:         5,
			window:        0,
			expectedError: ErrInvalidWindow,
		},
		{
			name:          "sub-millisecond window",
			ctx:           context.Background(),
			key:           "rate_limit:login:ip:192.0.2.1",
			eventID:       "request-1",
			limit:         5,
			window:        500 * time.Microsecond,
			expectedError: ErrInvalidWindow,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := limiter.Allow(
				test.ctx,
				test.key,
				test.eventID,
				test.limit,
				test.window,
			)

			if !errors.Is(err, test.expectedError) {
				t.Fatalf(
					"expected error %v, got %v",
					test.expectedError,
					err,
				)
			}
		})
	}
}

func TestNewSlidingWindowValidatesDependencies(t *testing.T) {
	t.Parallel()

	_, err := NewSlidingWindow(nil, testOperationTimeout)
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf(
			"expected ErrNotInitialized, got %v",
			err,
		)
	}

	client := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:1",
	})
	t.Cleanup(func() {
		_ = client.Close()
	})

	_, err = NewSlidingWindow(client, 0)
	if !errors.Is(err, ErrInvalidOperationTimeout) {
		t.Fatalf(
			"expected ErrInvalidOperationTimeout, got %v",
			err,
		)
	}
}

func TestNilSlidingWindowIsRejected(t *testing.T) {
	t.Parallel()

	var limiter *SlidingWindow

	_, err := limiter.Allow(
		context.Background(),
		"rate_limit:login:ip:192.0.2.1",
		"request-1",
		5,
		time.Minute,
	)

	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf(
			"expected ErrNotInitialized, got %v",
			err,
		)
	}
}

func TestParseScriptResultRejectsMalformedResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rawResult []any
	}{
		{
			name:      "wrong number of values",
			rawResult: []any{int64(1)},
		},
		{
			name: "invalid allowed value",
			rawResult: []any{
				int64(2),
				int64(0),
				int64(0),
			},
		},
		{
			name: "negative remaining value",
			rawResult: []any{
				int64(1),
				int64(-1),
				int64(0),
			},
		},
		{
			name: "allowed result with retry after",
			rawResult: []any{
				int64(1),
				int64(0),
				int64(100),
			},
		},
		{
			name: "rejected result with remaining capacity",
			rawResult: []any{
				int64(0),
				int64(1),
				int64(100),
			},
		},
		{
			name: "unsupported result type",
			rawResult: []any{
				true,
				int64(0),
				int64(0),
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseScriptResult(test.rawResult)

			if !errors.Is(err, ErrUnexpectedScriptResult) {
				t.Fatalf(
					"expected ErrUnexpectedScriptResult, got %v",
					err,
				)
			}
		})
	}
}

func newTestLimiter(
	t *testing.T,
) (*miniredis.Miniredis, *redis.Client, *SlidingWindow) {
	t.Helper()

	server := miniredis.RunT(t)

	server.SetTime(
		time.Date(
			2026,
			time.July,
			30,
			9,
			0,
			0,
			0,
			time.UTC,
		),
	)

	client := redis.NewClient(&redis.Options{
		Addr: server.Addr(),
	})

	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close Redis client: %v", err)
		}
	})

	limiter, err := NewSlidingWindow(
		client,
		testOperationTimeout,
	)
	if err != nil {
		t.Fatalf("create sliding-window limiter: %v", err)
	}

	return server, client, limiter
}
