package cleanup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"
)

const maxBatchSize = 10000

var (
	ErrDependencyMissing = errors.New("cleanup dependency is missing")
	ErrInvalidConfig     = errors.New("cleanup configuration is invalid")
)

type Config struct {
	Interval              time.Duration
	DatabaseTimeout       time.Duration
	BatchSize             int
	LoginAttemptRetention time.Duration
	TokenRetention        time.Duration
	OutboxRetention       time.Duration
}

type Params struct {
	LoginAttemptsBefore   time.Time
	TokensExpiredBefore   time.Time
	OutboxProcessedBefore time.Time
	BatchSize             int
}

type Stats struct {
	LoginAttemptsDeleted       int64
	VerificationTokensDeleted  int64
	PasswordResetTokensDeleted int64
	OutboxEventsDeleted        int64
}

type Repository interface {
	Cleanup(ctx context.Context, params Params) (Stats, error)
}

type Worker struct {
	repository Repository
	logger     *slog.Logger
	config     Config
	now        func() time.Time
}

func NewWorker(
	repository Repository,
	logger *slog.Logger,
	config Config,
	now func() time.Time,
) (*Worker, error) {
	if repository == nil || logger == nil || now == nil {
		return nil, ErrDependencyMissing
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	return &Worker{
		repository: repository,
		logger:     logger,
		config:     config,
		now:        now,
	}, nil
}

func (w *Worker) Run(ctx context.Context) {
	if w == nil || ctx == nil {
		return
	}

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			w.runSafely(ctx)
			timer.Reset(w.config.Interval)
		}
	}
}

func (w *Worker) runSafely(ctx context.Context) {
	defer func() {
		if recovered := recover(); recovered != nil {
			w.logger.Error(
				"cleanup worker panic recovered",
				slog.Any("panic", recovered),
				slog.String("stack", string(debug.Stack())),
			)
		}
	}()

	now := w.now().UTC().Truncate(time.Second)
	if now.IsZero() {
		w.logger.Error("cleanup worker clock returned zero time")
		return
	}

	operationContext, cancelOperation := context.WithTimeout(
		ctx,
		w.config.DatabaseTimeout,
	)
	defer cancelOperation()

	stats, err := w.repository.Cleanup(
		operationContext,
		Params{
			LoginAttemptsBefore:   now.Add(-w.config.LoginAttemptRetention),
			TokensExpiredBefore:   now.Add(-w.config.TokenRetention),
			OutboxProcessedBefore: now.Add(-w.config.OutboxRetention),
			BatchSize:             w.config.BatchSize,
		},
	)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		w.logger.Error(
			"cleanup cycle failed",
			slog.String("error", err.Error()),
		)
		return
	}

	w.logger.Info(
		"cleanup cycle completed",
		slog.Int64("login_attempts_deleted", stats.LoginAttemptsDeleted),
		slog.Int64("verification_tokens_deleted", stats.VerificationTokensDeleted),
		slog.Int64("password_reset_tokens_deleted", stats.PasswordResetTokensDeleted),
		slog.Int64("outbox_events_deleted", stats.OutboxEventsDeleted),
	)
}

func validateConfig(config Config) error {
	switch {
	case config.Interval <= 0:
		return fmt.Errorf("%w: interval must be positive", ErrInvalidConfig)
	case config.DatabaseTimeout <= 0:
		return fmt.Errorf("%w: database timeout must be positive", ErrInvalidConfig)
	case config.BatchSize <= 0 || config.BatchSize > maxBatchSize:
		return fmt.Errorf(
			"%w: batch size must be between 1 and %d",
			ErrInvalidConfig,
			maxBatchSize,
		)
	case config.LoginAttemptRetention != 30*24*time.Hour:
		return fmt.Errorf(
			"%w: login attempt retention must be exactly 30 days",
			ErrInvalidConfig,
		)
	case config.TokenRetention <= 0:
		return fmt.Errorf("%w: token retention must be positive", ErrInvalidConfig)
	case config.OutboxRetention <= 0:
		return fmt.Errorf("%w: outbox retention must be positive", ErrInvalidConfig)
	}
	return nil
}
