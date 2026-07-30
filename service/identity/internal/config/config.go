package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPPort            = 8080
	defaultHTTPShutdownTimeout = 10 * time.Second

	defaultDatabaseConnectTimeout = 5 * time.Second

	defaultRedisConnectTimeout = 3 * time.Second
	defaultRedisDB             = 0

	defaultRateLimitOperationTimeout = 500 * time.Millisecond
	minimumSecretByteLength          = 32

	defaultSignupIPLimit     = 5
	defaultSignupIPWindow    = 15 * time.Minute
	defaultSignupEmailLimit  = 3
	defaultSignupEmailWindow = time.Hour

	defaultLoginIPLimit     = 20
	defaultLoginIPWindow    = 15 * time.Minute
	defaultLoginEmailLimit  = 5
	defaultLoginEmailWindow = 15 * time.Minute

	defaultResendVerificationIPLimit     = 5
	defaultResendVerificationIPWindow    = 15 * time.Minute
	defaultResendVerificationEmailLimit  = 3
	defaultResendVerificationEmailWindow = time.Hour

	defaultSessionOperationTimeout = 500 * time.Millisecond

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
	Token      TokenConfig
	Session    SessionConfig
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
	KeySecret          string
	OperationTimeout   time.Duration
	Signup             EmailIPRateLimitConfig
	Login              EmailIPRateLimitConfig
	ResendVerification EmailIPRateLimitConfig
}

type EmailIPRateLimitConfig struct {
	IPLimit     int64
	IPWindow    time.Duration
	EmailLimit  int64
	EmailWindow time.Duration
}

type TokenConfig struct {
	JWTSecret     string
	RefreshSecret string
}

type SessionConfig struct {
	OperationTimeout time.Duration
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
	httpConfig, err := loadHTTPConfig()
	if err != nil {
		return Config{}, err
	}

	postgresConfig, err := loadPostgreSQLConfig()
	if err != nil {
		return Config{}, err
	}

	redisConfig, err := loadRedisConfig()
	if err != nil {
		return Config{}, err
	}

	rateLimitConfig, err := loadRateLimitConfig()
	if err != nil {
		return Config{}, err
	}

	tokenConfig, err := loadTokenConfig()
	if err != nil {
		return Config{}, err
	}

	sessionConfig, err := loadSessionConfig()
	if err != nil {
		return Config{}, err
	}

	emailConfig, err := loadEmailConfig()
	if err != nil {
		return Config{}, err
	}

	outboxConfig, err := loadOutboxConfig()
	if err != nil {
		return Config{}, err
	}

	return Config{
		HTTP:       httpConfig,
		PostgreSQL: postgresConfig,
		Redis:      redisConfig,
		RateLimit:  rateLimitConfig,
		Token:      tokenConfig,
		Session:    sessionConfig,
		Email:      emailConfig,
		Outbox:     outboxConfig,
	}, nil
}

func loadHTTPConfig() (HTTPConfig, error) {
	httpPort, err := readInt("HTTP_PORT", defaultHTTPPort)
	if err != nil {
		return HTTPConfig{}, fmt.Errorf("read HTTP_PORT: %w", err)
	}

	if httpPort < 1 || httpPort > 65535 {
		return HTTPConfig{}, fmt.Errorf(
			"HTTP_PORT must be between 1 and 65535",
		)
	}

	shutdownTimeout, err := readPositiveDuration(
		"HTTP_SHUTDOWN_TIMEOUT",
		defaultHTTPShutdownTimeout,
	)
	if err != nil {
		return HTTPConfig{}, err
	}

	return HTTPConfig{
		Addr:            fmt.Sprintf(":%d", httpPort),
		ShutdownTimeout: shutdownTimeout,
	}, nil
}

func loadPostgreSQLConfig() (PostgreSQLConfig, error) {
	databaseURL, err := requiredString("DATABASE_URL")
	if err != nil {
		return PostgreSQLConfig{}, err
	}

	connectTimeout, err := readPositiveDuration(
		"DATABASE_CONNECT_TIMEOUT",
		defaultDatabaseConnectTimeout,
	)
	if err != nil {
		return PostgreSQLConfig{}, err
	}

	return PostgreSQLConfig{
		URL:            databaseURL,
		ConnectTimeout: connectTimeout,
	}, nil
}

func loadRedisConfig() (RedisConfig, error) {
	address, err := requiredString("REDIS_ADDR")
	if err != nil {
		return RedisConfig{}, err
	}

	databaseNumber, err := readInt("REDIS_DB", defaultRedisDB)
	if err != nil {
		return RedisConfig{}, fmt.Errorf("read REDIS_DB: %w", err)
	}

	if databaseNumber < 0 {
		return RedisConfig{}, fmt.Errorf("REDIS_DB must not be negative")
	}

	connectTimeout, err := readPositiveDuration(
		"REDIS_CONNECT_TIMEOUT",
		defaultRedisConnectTimeout,
	)
	if err != nil {
		return RedisConfig{}, err
	}

	return RedisConfig{
		Addr: address,
		Username: strings.TrimSpace(
			os.Getenv("REDIS_USERNAME"),
		),
		Password:       os.Getenv("REDIS_PASSWORD"),
		DB:             databaseNumber,
		ConnectTimeout: connectTimeout,
	}, nil
}

func loadRateLimitConfig() (RateLimitConfig, error) {
	keySecret, err := requiredSecret("RATE_LIMIT_KEY_SECRET")
	if err != nil {
		return RateLimitConfig{}, err
	}

	operationTimeout, err := readPositiveDuration(
		"RATE_LIMIT_OPERATION_TIMEOUT",
		defaultRateLimitOperationTimeout,
	)
	if err != nil {
		return RateLimitConfig{}, err
	}

	signup, err := loadEmailIPRateLimit(
		"SIGNUP_RATE_LIMIT",
		defaultSignupIPLimit,
		defaultSignupIPWindow,
		defaultSignupEmailLimit,
		defaultSignupEmailWindow,
	)
	if err != nil {
		return RateLimitConfig{}, err
	}

	login, err := loadEmailIPRateLimit(
		"LOGIN_RATE_LIMIT",
		defaultLoginIPLimit,
		defaultLoginIPWindow,
		defaultLoginEmailLimit,
		defaultLoginEmailWindow,
	)
	if err != nil {
		return RateLimitConfig{}, err
	}

	resendVerification, err := loadEmailIPRateLimit(
		"RESEND_VERIFICATION_RATE_LIMIT",
		defaultResendVerificationIPLimit,
		defaultResendVerificationIPWindow,
		defaultResendVerificationEmailLimit,
		defaultResendVerificationEmailWindow,
	)
	if err != nil {
		return RateLimitConfig{}, err
	}

	return RateLimitConfig{
		KeySecret:          keySecret,
		OperationTimeout:   operationTimeout,
		Signup:             signup,
		Login:              login,
		ResendVerification: resendVerification,
	}, nil
}

func loadEmailIPRateLimit(
	prefix string,
	defaultIPLimit int,
	defaultIPWindow time.Duration,
	defaultEmailLimit int,
	defaultEmailWindow time.Duration,
) (EmailIPRateLimitConfig, error) {
	ipLimit, err := readPositiveInt(
		prefix+"_IP_REQUESTS",
		defaultIPLimit,
	)
	if err != nil {
		return EmailIPRateLimitConfig{}, err
	}

	ipWindow, err := readPositiveDuration(
		prefix+"_IP_WINDOW",
		defaultIPWindow,
	)
	if err != nil {
		return EmailIPRateLimitConfig{}, err
	}

	emailLimit, err := readPositiveInt(
		prefix+"_EMAIL_REQUESTS",
		defaultEmailLimit,
	)
	if err != nil {
		return EmailIPRateLimitConfig{}, err
	}

	emailWindow, err := readPositiveDuration(
		prefix+"_EMAIL_WINDOW",
		defaultEmailWindow,
	)
	if err != nil {
		return EmailIPRateLimitConfig{}, err
	}

	return EmailIPRateLimitConfig{
		IPLimit:     int64(ipLimit),
		IPWindow:    ipWindow,
		EmailLimit:  int64(emailLimit),
		EmailWindow: emailWindow,
	}, nil
}

func loadTokenConfig() (TokenConfig, error) {
	jwtSecret, err := requiredSecret("JWT_HS256_SECRET")
	if err != nil {
		return TokenConfig{}, err
	}

	refreshSecret, err := requiredSecret("REFRESH_TOKEN_SECRET")
	if err != nil {
		return TokenConfig{}, err
	}

	if jwtSecret == refreshSecret {
		return TokenConfig{}, fmt.Errorf(
			"JWT_HS256_SECRET and REFRESH_TOKEN_SECRET must be different",
		)
	}

	return TokenConfig{
		JWTSecret:     jwtSecret,
		RefreshSecret: refreshSecret,
	}, nil
}

func loadSessionConfig() (SessionConfig, error) {
	operationTimeout, err := readPositiveDuration(
		"SESSION_OPERATION_TIMEOUT",
		defaultSessionOperationTimeout,
	)
	if err != nil {
		return SessionConfig{}, err
	}

	return SessionConfig{
		OperationTimeout: operationTimeout,
	}, nil
}

func loadEmailConfig() (EmailConfig, error) {
	smtpHost := optionalString("SMTP_HOST", defaultSMTPHost)

	smtpPort, err := readPositiveInt("SMTP_PORT", defaultSMTPPort)
	if err != nil {
		return EmailConfig{}, err
	}

	if smtpPort > 65535 {
		return EmailConfig{}, fmt.Errorf("SMTP_PORT must not exceed 65535")
	}

	smtpUsername, err := requiredString("SMTP_USERNAME")
	if err != nil {
		return EmailConfig{}, err
	}

	smtpAppPassword, err := requiredRawString("SMTP_APP_PASSWORD")
	if err != nil {
		return EmailConfig{}, err
	}

	smtpAppPassword = strings.ReplaceAll(smtpAppPassword, " ", "")
	if smtpAppPassword == "" {
		return EmailConfig{}, fmt.Errorf("SMTP_APP_PASSWORD is required")
	}

	smtpFromAddress := strings.TrimSpace(os.Getenv("SMTP_FROM_ADDRESS"))
	if smtpFromAddress == "" {
		smtpFromAddress = smtpUsername
	}

	smtpTimeout, err := readPositiveDuration(
		"SMTP_TIMEOUT",
		defaultSMTPTimeout,
	)
	if err != nil {
		return EmailConfig{}, err
	}

	verificationURL, err := requiredString("EMAIL_VERIFICATION_URL")
	if err != nil {
		return EmailConfig{}, err
	}

	return EmailConfig{
		SMTPHost:        smtpHost,
		SMTPPort:        smtpPort,
		SMTPUsername:    smtpUsername,
		SMTPAppPassword: smtpAppPassword,
		SMTPFromName: optionalString(
			"SMTP_FROM_NAME",
			defaultSMTPFromName,
		),
		SMTPFromAddress: smtpFromAddress,
		SMTPTimeout:     smtpTimeout,
		VerificationURL: verificationURL,
	}, nil
}

func loadOutboxConfig() (OutboxConfig, error) {
	pollInterval, err := readPositiveDuration(
		"OUTBOX_POLL_INTERVAL",
		defaultOutboxPollInterval,
	)
	if err != nil {
		return OutboxConfig{}, err
	}

	batchSize, err := readPositiveInt(
		"OUTBOX_BATCH_SIZE",
		defaultOutboxBatchSize,
	)
	if err != nil {
		return OutboxConfig{}, err
	}

	lockTimeout, err := readPositiveDuration(
		"OUTBOX_LOCK_TIMEOUT",
		defaultOutboxLockTimeout,
	)
	if err != nil {
		return OutboxConfig{}, err
	}

	databaseTimeout, err := readPositiveDuration(
		"OUTBOX_DATABASE_TIMEOUT",
		defaultOutboxDatabaseTimeout,
	)
	if err != nil {
		return OutboxConfig{}, err
	}

	deliveryTimeout, err := readPositiveDuration(
		"OUTBOX_DELIVERY_TIMEOUT",
		defaultOutboxDeliveryTimeout,
	)
	if err != nil {
		return OutboxConfig{}, err
	}

	retryBase, err := readPositiveDuration(
		"OUTBOX_RETRY_BASE",
		defaultOutboxRetryBase,
	)
	if err != nil {
		return OutboxConfig{}, err
	}

	retryMax, err := readPositiveDuration(
		"OUTBOX_RETRY_MAX",
		defaultOutboxRetryMax,
	)
	if err != nil {
		return OutboxConfig{}, err
	}

	return OutboxConfig{
		PollInterval:    pollInterval,
		BatchSize:       batchSize,
		LockTimeout:     lockTimeout,
		DatabaseTimeout: databaseTimeout,
		DeliveryTimeout: deliveryTimeout,
		RetryBase:       retryBase,
		RetryMax:        retryMax,
	}, nil
}

func requiredSecret(key string) (string, error) {
	value, err := requiredRawString(key)
	if err != nil {
		return "", err
	}

	if len(value) < minimumSecretByteLength {
		return "", fmt.Errorf(
			"%s must contain at least %d bytes",
			key,
			minimumSecretByteLength,
		)
	}

	return value, nil
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

func optionalString(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	return value
}

func readPositiveInt(key string, fallback int) (int, error) {
	value, err := readInt(key, fallback)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", key, err)
	}

	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
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
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}

	return parsed, nil
}

func readPositiveDuration(
	key string,
	fallback time.Duration,
) (time.Duration, error) {
	value, err := readDuration(key, fallback)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", key, err)
	}

	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", key)
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
		return 0, fmt.Errorf("%s must be a valid duration: %w", key, err)
	}

	return parsed, nil
}
