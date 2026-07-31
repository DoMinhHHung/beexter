package cleanup

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestWorkerRunsCleanupWithLockedRetention(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 31, 6, 0, 0, 0, time.UTC)
	called := make(chan Params, 1)
	repository := cleanupRepositoryFunc(func(_ context.Context, params Params) (Stats, error) {
		called <- params
		return Stats{LoginAttemptsDeleted: 1}, nil
	})
	worker, err := NewWorker(
		repository,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		Config{
			Interval:              time.Hour,
			DatabaseTimeout:       time.Second,
			BatchSize:             100,
			LoginAttemptRetention: 30 * 24 * time.Hour,
			TokenRetention:        24 * time.Hour,
			OutboxRetention:       7 * 24 * time.Hour,
		},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("create worker: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		worker.Run(ctx)
	}()

	select {
	case params := <-called:
		if !params.LoginAttemptsBefore.Equal(now.Add(-30*24*time.Hour)) ||
			!params.TokensExpiredBefore.Equal(now.Add(-24*time.Hour)) ||
			!params.OutboxProcessedBefore.Equal(now.Add(-7*24*time.Hour)) {
			t.Fatalf("unexpected cleanup cutoffs: %+v", params)
		}
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("cleanup worker did not run")
	}
	<-done
}

func TestNewWorkerRejectsChangedLoginRetention(t *testing.T) {
	t.Parallel()

	_, err := NewWorker(
		cleanupRepositoryFunc(func(context.Context, Params) (Stats, error) { return Stats{}, nil }),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		Config{
			Interval:              time.Hour,
			DatabaseTimeout:       time.Second,
			BatchSize:             100,
			LoginAttemptRetention: 29 * 24 * time.Hour,
			TokenRetention:        time.Hour,
			OutboxRetention:       time.Hour,
		},
		time.Now,
	)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

type cleanupRepositoryFunc func(context.Context, Params) (Stats, error)

func (f cleanupRepositoryFunc) Cleanup(ctx context.Context, params Params) (Stats, error) {
	return f(ctx, params)
}
