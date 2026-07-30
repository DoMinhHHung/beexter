package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPPort               = 8080
	defaultHTTPShutdownTimeout    = 10 * time.Second
	defaultDatabaseConnectTimeout = 5 * time.Second
	defaultRedisConnectTimeout    = 3 * time.Second
	defaultRedisDB                = 0

	defaultRateLimitOperationTimeout = 500 * time.Millisecond
	defaultSignupIPLimit             = 5
	defaultSignupIPWindow            = 15 * time.Minute
	defaultSignupEmailLimit          = 3
	defaultSignupEmailWindow         = time.Hour
	minimumKeySecretByteLength       = 32

	defaultSMTPHost     = "smtp.gmail.com"
	defaultSMTPPort     = 587
	defaultSMTPFromName = "Beexter"
	defaultSMTPTimeout  = 10 * time.Second

	defaultOutboxPollInterval    = 2 * time.Second
	defaultOutboxBatchSize       = 10
	defaultOutboxLockTimeout     = 5 * time.Minute
	defaultOutboxDatabaseTimeout = 3 * time.Second
	defaultOutboxDeliveryTimeout = 15 * time.Second
	defaultOutboxRetryBase       = 5 * time.Second
	defaultOutboxRetryMax        = time.Hour
)

type Config struct {
	HTTP       HTTPConfig
	PostgreSQL PostgreSQLConfig
	Redis      RedisConfig
	RateLimit  RateLimitConfig
	Email      EmailConfig
	Outbox     OutboxConfig
}

type HTTPConfig struct {
	Addr            string
	ShutdownTimeout time.Duration
}

type PostgreSQLConfig struct {
	URL            string
	ConnectTimeout time.Duration
}

type RedisConfig struct {
	Addr           string
	Username       string
	Password       string
	DB             int
	ConnectTimeout time.Duration
}

type RateLimitConfig struct {
	KeySecret        string
	OperationTimeout time.Duration
	Signup           SignupRateLimitConfig
}

type SignupRateLimitConfig struct {
	IPLimit     int64
	IPWindow    time.Duration
	EmailLimit  int64
	EmailWindow time.Duration
}

type EmailConfig struct {
	SMTPHost        string
	SMTPPort        int
	SMTPUsername    string
	SMTPAppPassword string
	SMTPFromName    string
	SMTPFromAddress string
	SMTPTimeout     time.Duration
	VerificationURL string
}

type OutboxConfig struct {
	PollInterval    time.Duration
	BatchSize       int
	LockTimeout     time.Duration
	DatabaseTimeout time.Duration
	DeliveryTimeout time.Duration
	RetryBase       time.Duration
	RetryMax        time.Duration
}

func Load() (Config, error) {
	httpPort, err := readInt("HTTP_PORT", defaultHTTPPort)
	if err != nil {
		return Config{}, fmt.Errorf("read HTTP_PORT: %w", err)
	}

	if httpPort < 1 || httpPort > 65535 {
		return Config{}, fmt.Errorf(
			"HTTP_PORT must be between 1 and 65535",
		)
	}

	shutdownTimeout, err := readPositiveDuration(
		"HTTP_SHUTDOWN_TIMEOUT",
		defaultHTTPShutdownTimeout,
	)
	if err != nil {
		return Config{}, err
	}

	databaseURL, err := requiredString("DATABASE_URL")
	if err != nil {
		return Config{}, err
	}

	databaseConnectTimeout, err := readPositiveDuration(
		"DATABASE_CONNECT_TIMEOUT",
		defaultDatabaseConnectTimeout,
	)
	if err != nil {
		return Config{}, err
	}

	redisAddr, err := requiredString("REDIS_ADDR")
	if err != nil {
		return Config{}, err
	}

	redisDB, err := readInt("REDIS_DB", defaultRedisDB)
	if err != nil {
		return Config{}, fmt.Errorf(
			"read REDIS_DB: %w",
			err,
		)
	}

	if redisDB < 0 {
		return Config{}, fmt.Errorf(
			"REDIS_DB must not be negative",
		)
	}

	redisConnectTimeout, err := readPositiveDuration(
		"REDIS_CONNECT_TIMEOUT",
		defaultRedisConnectTimeout,
	)
	if err != nil {
		return Config{}, err
	}

	rateLimitKeySecret, err := requiredRawString(
		"RATE_LIMIT_KEY_SECRET",
	)
	if err != nil {
		return Config{}, err
	}

	if len(rateLimitKeySecret) < minimumKeySecretByteLength {
		return Config{}, fmt.Errorf(
			"RATE_LIMIT_KEY_SECRET must contain at least %d bytes",
			minimumKeySecretByteLength,
		)
	}

	rateLimitOperationTimeout, err :=
		readPositiveDuration(
			"RATE_LIMIT_OPERATION_TIMEOUT",
			defaultRateLimitOperationTimeout,
		)
	if err != nil {
		return Config{}, err
	}

	signupIPLimit, err := readPositiveInt(
		"SIGNUP_RATE_LIMIT_IP_REQUESTS",
		defaultSignupIPLimit,
	)
	if err != nil {
		return Config{}, err
	}

	signupIPWindow, err := readPositiveDuration(
		"SIGNUP_RATE_LIMIT_IP_WINDOW",
		defaultSignupIPWindow,
	)
	if err != nil {
		return Config{}, err
	}

	signupEmailLimit, err := readPositiveInt(
		"SIGNUP_RATE_LIMIT_EMAIL_REQUESTS",
		defaultSignupEmailLimit,
	)
	if err != nil {
		return Config{}, err
	}

	signupEmailWindow, err := readPositiveDuration(
		"SIGNUP_RATE_LIMIT_EMAIL_WINDOW",
		defaultSignupEmailWindow,
	)
	if err != nil {
		return Config{}, err
	}

	smtpHost := optionalString(
		"SMTP_HOST",
		defaultSMTPHost,
	)

	smtpPort, err := readPositiveInt(
		"SMTP_PORT",
		defaultSMTPPort,
	)
	if err != nil {
		return Config{}, err
	}

	if smtpPort > 65535 {
		return Config{}, fmt.Errorf(
			"SMTP_PORT must not exceed 65535",
		)
	}

	smtpUsername, err := requiredString("SMTP_USERNAME")
	if err != nil {
		return Config{}, err
	}

	smtpAppPassword, err := requiredRawString(
		"SMTP_APP_PASSWORD",
	)
	if err != nil {
		return Config{}, err
	}

	smtpAppPassword = strings.ReplaceAll(
		smtpAppPassword,
		" ",
		"",
	)

	if smtpAppPassword == "" {
		return Config{}, fmt.Errorf(
			"SMTP_APP_PASSWORD is required",
		)
	}

	smtpFromName := optionalString(
		"SMTP_FROM_NAME",
		defaultSMTPFromName,
	)

	smtpFromAddress := strings.TrimSpace(
		os.Getenv("SMTP_FROM_ADDRESS"),
	)
	if smtpFromAddress == "" {
		smtpFromAddress = smtpUsername
	}

	smtpTimeout, err := readPositiveDuration(
		"SMTP_TIMEOUT",
		defaultSMTPTimeout,
	)
	if err != nil {
		return Config{}, err
	}

	verificationURL, err := requiredString(
		"EMAIL_VERIFICATION_URL",
	)
	if err != nil {
		return Config{}, err
	}

	outboxPollInterval, err := readPositiveDuration(
		"OUTBOX_POLL_INTERVAL",
		defaultOutboxPollInterval,
	)
	if err != nil {
		return Config{}, err
	}

	outboxBatchSize, err := readPositiveInt(
		"OUTBOX_BATCH_SIZE",
		defaultOutboxBatchSize,
	)
	if err != nil {
		return Config{}, err
	}

	outboxLockTimeout, err := readPositiveDuration(
		"OUTBOX_LOCK_TIMEOUT",
		defaultOutboxLockTimeout,
	)
	if err != nil {
		return Config{}, err
	}

	outboxDatabaseTimeout, err := readPositiveDuration(
		"OUTBOX_DATABASE_TIMEOUT",
		defaultOutboxDatabaseTimeout,
	)
	if err != nil {
		return Config{}, err
	}

	outboxDeliveryTimeout, err := readPositiveDuration(
		"OUTBOX_DELIVERY_TIMEOUT",
		defaultOutboxDeliveryTimeout,
	)
	if err != nil {
		return Config{}, err
	}

	outboxRetryBase, err := readPositiveDuration(
		"OUTBOX_RETRY_BASE",
		defaultOutboxRetryBase,
	)
	if err != nil {
		return Config{}, err
	}

	outboxRetryMax, err := readPositiveDuration(
		"OUTBOX_RETRY_MAX",
		defaultOutboxRetryMax,
	)
	if err != nil {
		return Config{}, err
	}

	return Config{
		HTTP: HTTPConfig{
			Addr:            fmt.Sprintf(":%d", httpPort),
			ShutdownTimeout: shutdownTimeout,
		},
		PostgreSQL: PostgreSQLConfig{
			URL:            databaseURL,
			ConnectTimeout: databaseConnectTimeout,
		},
		Redis: RedisConfig{
			Addr: redisAddr,
			Username: strings.TrimSpace(
				os.Getenv("REDIS_USERNAME"),
			),
			Password:       os.Getenv("REDIS_PASSWORD"),
			DB:             redisDB,
			ConnectTimeout: redisConnectTimeout,
		},
		RateLimit: RateLimitConfig{
			KeySecret:        rateLimitKeySecret,
			OperationTimeout: rateLimitOperationTimeout,
			Signup: SignupRateLimitConfig{
				IPLimit:     int64(signupIPLimit),
				IPWindow:    signupIPWindow,
				EmailLimit:  int64(signupEmailLimit),
				EmailWindow: signupEmailWindow,
			},
		},
		Email: EmailConfig{
			SMTPHost:        smtpHost,
			SMTPPort:        smtpPort,
			SMTPUsername:    smtpUsername,
			SMTPAppPassword: smtpAppPassword,
			SMTPFromName:    smtpFromName,
			SMTPFromAddress: smtpFromAddress,
			SMTPTimeout:     smtpTimeout,
			VerificationURL: verificationURL,
		},
		Outbox: OutboxConfig{
			PollInterval:    outboxPollInterval,
			BatchSize:       outboxBatchSize,
			LockTimeout:     outboxLockTimeout,
			DatabaseTimeout: outboxDatabaseTimeout,
			DeliveryTimeout: outboxDeliveryTimeout,
			RetryBase:       outboxRetryBase,
			RetryMax:        outboxRetryMax,
		},
	}, nil
}

func requiredString(key string) (string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}

	return value, nil
}

func requiredRawString(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}

	return value, nil
}

func optionalString(
	key string,
	fallback string,
) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	return value
}

func readPositiveInt(
	key string,
	fallback int,
) (int, error) {
	value, err := readInt(key, fallback)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", key, err)
	}

	if value <= 0 {
		return 0, fmt.Errorf(
			"%s must be greater than zero",
			key,
		)
	}

	return value, nil
}

func readInt(key string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf(
			"%s must be an integer: %w",
			key,
			err,
		)
	}

	return parsed, nil
}

func readPositiveDuration(
	key string,
	fallback time.Duration,
) (time.Duration, error) {
	value, err := readDuration(key, fallback)
	if err != nil {
		return 0, fmt.Errorf(
			"read %s: %w",
			key,
			err,
		)
	}

	if value <= 0 {
		return 0, fmt.Errorf(
			"%s must be greater than zero",
			key,
		)
	}

	return value, nil
}

func readDuration(
	key string,
	fallback time.Duration,
) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf(
			"%s must be a valid duration: %w",
			key,
			err,
		)
	}

	return parsed, nil
}
