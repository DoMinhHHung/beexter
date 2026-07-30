package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	loginapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/login"
	outboxapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/outbox"
	resendverificationapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/resendverification"
	signupapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/signup"
	verifyemailapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/verifyemail"
	"github.com/DoMinhHHung/beexter/service/identity/internal/config"
	"github.com/DoMinhHHung/beexter/service/identity/internal/httpapi"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/accesstoken"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/emaildelivery"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/idgen"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/passwordhash"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/postgres"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/ratelimit"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/redisclient"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/refreshtoken"
	"github.com/DoMinhHHung/beexter/service/identity/internal/platform/session"
)

const dummyLoginPassword = "BeexterDummyAuthentication1!"

func main() {
	logger := slog.New(
		slog.NewJSONHandler(
			os.Stdout,
			&slog.HandlerOptions{
				Level: slog.LevelInfo,
			},
		),
	)

	if err := run(logger); err != nil {
		logger.Error(
			"application stopped unexpectedly",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	applicationContext, stopApplication := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stopApplication()

	databaseContext, cancelDatabase := context.WithTimeout(
		applicationContext,
		cfg.PostgreSQL.ConnectTimeout,
	)

	database, err := postgres.Open(
		databaseContext,
		cfg.PostgreSQL.URL,
	)
	cancelDatabase()
	if err != nil {
		return fmt.Errorf("open PostgreSQL: %w", err)
	}
	defer database.Close()

	redisContext, cancelRedis := context.WithTimeout(
		applicationContext,
		cfg.Redis.ConnectTimeout,
	)

	cache, err := redisclient.Open(redisContext, cfg.Redis)
	cancelRedis()
	if err != nil {
		return fmt.Errorf("open Redis: %w", err)
	}

	defer func() {
		if err := cache.Close(); err != nil {
			logger.Warn(
				"failed to close Redis client",
				slog.String("error", err.Error()),
			)
		}
	}()

	rateLimitKeys, err := ratelimit.NewKeyBuilder(
		cfg.RateLimit.KeySecret,
	)
	if err != nil {
		return fmt.Errorf("create rate-limit key builder: %w", err)
	}

	slidingWindowLimiter, err := ratelimit.NewSlidingWindow(
		cache,
		cfg.RateLimit.OperationTimeout,
	)
	if err != nil {
		return fmt.Errorf("create sliding-window rate limiter: %w", err)
	}

	signupLimiter, err := ratelimit.NewSignupLimiter(
		slidingWindowLimiter,
		rateLimitKeys,
		ratelimit.SignupPolicy{
			IPLimit:     cfg.RateLimit.Signup.IPLimit,
			IPWindow:    cfg.RateLimit.Signup.IPWindow,
			EmailLimit:  cfg.RateLimit.Signup.EmailLimit,
			EmailWindow: cfg.RateLimit.Signup.EmailWindow,
		},
	)
	if err != nil {
		return fmt.Errorf("create signup rate limiter: %w", err)
	}

	loginLimiter, err := ratelimit.NewLoginLimiter(
		slidingWindowLimiter,
		rateLimitKeys,
		ratelimit.LoginPolicy{
			IPLimit:     cfg.RateLimit.Login.IPLimit,
			IPWindow:    cfg.RateLimit.Login.IPWindow,
			EmailLimit:  cfg.RateLimit.Login.EmailLimit,
			EmailWindow: cfg.RateLimit.Login.EmailWindow,
		},
	)
	if err != nil {
		return fmt.Errorf("create login rate limiter: %w", err)
	}

	resendVerificationLimiter, err := ratelimit.NewResendVerificationLimiter(
		slidingWindowLimiter,
		rateLimitKeys,
		ratelimit.ResendVerificationPolicy{
			IPLimit:     cfg.RateLimit.ResendVerification.IPLimit,
			IPWindow:    cfg.RateLimit.ResendVerification.IPWindow,
			EmailLimit:  cfg.RateLimit.ResendVerification.EmailLimit,
			EmailWindow: cfg.RateLimit.ResendVerification.EmailWindow,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"create resend-verification rate limiter: %w",
			err,
		)
	}

	signupRepository, err := postgres.NewSignupRepository(database)
	if err != nil {
		return fmt.Errorf("create signup repository: %w", err)
	}

	loginRepository, err := postgres.NewLoginRepository(database)
	if err != nil {
		return fmt.Errorf("create login repository: %w", err)
	}

	verifyEmailRepository, err := postgres.NewVerifyEmailRepository(database)
	if err != nil {
		return fmt.Errorf("create verify-email repository: %w", err)
	}

	resendVerificationRepository, err :=
		postgres.NewResendVerificationRepository(database)
	if err != nil {
		return fmt.Errorf(
			"create resend-verification repository: %w",
			err,
		)
	}

	passwordHasher := passwordhash.New()
	identifierGenerator := idgen.NewUUIDV7()

	dummyPasswordHash, err := passwordHasher.Hash(dummyLoginPassword)
	if err != nil {
		return fmt.Errorf("create dummy login password hash: %w", err)
	}

	accessTokenService, err := accesstoken.New(cfg.Token.JWTSecret)
	if err != nil {
		return fmt.Errorf("create access-token service: %w", err)
	}

	refreshTokenCodec, err := refreshtoken.New(
		cfg.Token.RefreshSecret,
	)
	if err != nil {
		return fmt.Errorf("create refresh-token codec: %w", err)
	}

	sessionStore, err := session.NewStore(
		cache,
		cfg.Session.OperationTimeout,
	)
	if err != nil {
		return fmt.Errorf("create session store: %w", err)
	}

	signupUseCase, err := signupapp.New(
		signupRepository,
		passwordHasher,
		identifierGenerator,
		identifierGenerator,
		signupLimiter,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create signup use case: %w", err)
	}

	loginUseCase, err := loginapp.New(
		loginRepository,
		passwordHasher,
		identifierGenerator,
		loginLimiter,
		accessTokenService,
		refreshTokenCodec,
		sessionStore,
		dummyPasswordHash,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create login use case: %w", err)
	}

	verifyEmailUseCase, err := verifyemailapp.New(
		verifyEmailRepository,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create verify-email use case: %w", err)
	}

	resendVerificationUseCase, err := resendverificationapp.New(
		resendVerificationRepository,
		identifierGenerator,
		resendVerificationLimiter,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf(
			"create resend-verification use case: %w",
			err,
		)
	}

	emailRenderer, err := emaildelivery.NewRenderer()
	if err != nil {
		return fmt.Errorf("create email renderer: %w", err)
	}

	smtpSender, err := emaildelivery.NewSMTPSender(
		emaildelivery.SMTPConfig{
			Host:        cfg.Email.SMTPHost,
			Port:        cfg.Email.SMTPPort,
			Username:    cfg.Email.SMTPUsername,
			AppPassword: cfg.Email.SMTPAppPassword,
			FromName:    cfg.Email.SMTPFromName,
			FromAddress: cfg.Email.SMTPFromAddress,
			Timeout:     cfg.Email.SMTPTimeout,
		},
		logger,
	)
	if err != nil {
		return fmt.Errorf("create SMTP sender: %w", err)
	}

	verificationMailer, err := emaildelivery.NewVerificationMailer(
		smtpSender,
		emailRenderer,
		cfg.Email.VerificationURL,
	)
	if err != nil {
		return fmt.Errorf("create verification mailer: %w", err)
	}

	outboxRepository, err := postgres.NewOutboxRepository(database)
	if err != nil {
		return fmt.Errorf("create outbox repository: %w", err)
	}

	outboxWorker, err := outboxapp.NewWorker(
		outboxRepository,
		verificationMailer,
		identifierGenerator,
		logger,
		outboxapp.WorkerConfig{
			PollInterval:    cfg.Outbox.PollInterval,
			BatchSize:       cfg.Outbox.BatchSize,
			LockTimeout:     cfg.Outbox.LockTimeout,
			DatabaseTimeout: cfg.Outbox.DatabaseTimeout,
			DeliveryTimeout: cfg.Outbox.DeliveryTimeout,
			RetryBase:       cfg.Outbox.RetryBase,
			RetryMax:        cfg.Outbox.RetryMax,
		},
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create outbox worker: %w", err)
	}

	handler := httpapi.NewRouter(
		logger,
		database,
		cache,
		signupUseCase,
		loginUseCase,
		verifyEmailUseCase,
		resendVerificationUseCase,
	)

	server := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		outboxWorker.Run(applicationContext)
	}()

	serverError := make(chan error, 1)
	go func() {
		logger.Info(
			"http server started",
			slog.String("address", server.Addr),
		)
		serverError <- server.ListenAndServe()
	}()

	var (
		runErr               error
		serverResultConsumed bool
	)

	select {
	case <-applicationContext.Done():
		logger.Info("shutdown signal received")

	case err := <-serverError:
		serverResultConsumed = true
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("serve HTTP: %w", err)
		}
	}

	stopApplication()

	shutdownContext, cancelShutdown := context.WithTimeout(
		context.Background(),
		cfg.HTTP.ShutdownTimeout,
	)
	defer cancelShutdown()

	if err := server.Shutdown(shutdownContext); err != nil {
		closeErr := server.Close()
		runErr = errors.Join(
			runErr,
			fmt.Errorf("shutdown HTTP server: %w", err),
			closeErr,
		)
	}

	if !serverResultConsumed {
		serveErr := <-serverError
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			runErr = errors.Join(
				runErr,
				fmt.Errorf("HTTP server stopped unexpectedly: %w", serveErr),
			)
		}
	}

	workerShutdownTimer := time.NewTimer(cfg.HTTP.ShutdownTimeout)
	defer workerShutdownTimer.Stop()

	select {
	case <-workerDone:
		logger.Info("outbox worker stopped gracefully")

	case <-workerShutdownTimer.C:
		runErr = errors.Join(
			runErr,
			errors.New("outbox worker shutdown timed out"),
		)
	}

	logger.Info("http server stopped gracefully")
	return runErr
}
