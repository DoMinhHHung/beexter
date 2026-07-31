package config

import (
	"fmt"
	"time"
)

const (
	defaultCleanupInterval        = time.Hour
	defaultCleanupDatabaseTimeout = 10 * time.Second
	defaultCleanupBatchSize       = 1000
	loginAttemptRetention         = 30 * 24 * time.Hour
	defaultTokenRetention         = 24 * time.Hour
	defaultOutboxRetention        = 7 * 24 * time.Hour
)

type CleanupConfig struct {
	Interval              time.Duration
	DatabaseTimeout       time.Duration
	BatchSize             int
	LoginAttemptRetention time.Duration
	TokenRetention        time.Duration
	OutboxRetention       time.Duration
}

func LoadCleanup() (CleanupConfig, error) {
	interval, err := readPositiveDuration(
		"CLEANUP_INTERVAL",
		defaultCleanupInterval,
	)
	if err != nil {
		return CleanupConfig{}, err
	}
	databaseTimeout, err := readPositiveDuration(
		"CLEANUP_DATABASE_TIMEOUT",
		defaultCleanupDatabaseTimeout,
	)
	if err != nil {
		return CleanupConfig{}, err
	}
	batchSize, err := readPositiveInt(
		"CLEANUP_BATCH_SIZE",
		defaultCleanupBatchSize,
	)
	if err != nil {
		return CleanupConfig{}, err
	}
	if batchSize > 10000 {
		return CleanupConfig{}, fmt.Errorf("CLEANUP_BATCH_SIZE must not exceed %d", 10000)
	}
	tokenRetention, err := readPositiveDuration(
		"CLEANUP_TOKEN_RETENTION",
		defaultTokenRetention,
	)
	if err != nil {
		return CleanupConfig{}, err
	}
	outboxRetention, err := readPositiveDuration(
		"CLEANUP_OUTBOX_RETENTION",
		defaultOutboxRetention,
	)
	if err != nil {
		return CleanupConfig{}, err
	}

	return CleanupConfig{
		Interval:              interval,
		DatabaseTimeout:       databaseTimeout,
		BatchSize:             batchSize,
		LoginAttemptRetention: loginAttemptRetention,
		TokenRetention:        tokenRetention,
		OutboxRetention:       outboxRetention,
	}, nil
}
