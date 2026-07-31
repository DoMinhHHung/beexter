package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	authenticateapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/authenticate"
	changepasswordapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/changepassword"
	cleanupapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/cleanup"
	createidentityapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/createidentity"
	deleteaccountapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/deleteaccount"
	forgotpasswordapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/forgotpassword"
	getmeapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/getme"
	loginapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/login"
	loginhistoryapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/loginhistory"
	outboxapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/outbox"
	refreshapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/refresh"
	requestreactivationapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/requestreactivation"
	resendverificationapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/resendverification"
	resetpasswordapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/resetpassword"
	sessionmanagementapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/sessionmanagement"
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

	accessTokenService, err := newAccessTokenService(cfg.Token)
	if err != nil {
		return err
	}

	forgotPasswordConfig, err := config.LoadForgotPassword()
	if err != nil {
		return fmt.Errorf("load forgot-password config: %w", err)
	}

	resetPasswordConfig, err := config.LoadResetPassword()
	if err != nil {
		return fmt.Errorf("load reset-password config: %w", err)
	}

	changePasswordConfig, err := config.LoadChangePassword()
	if err != nil {
		return fmt.Errorf("load change-password config: %w", err)
	}

	accountLifecycleConfig, err := config.LoadAccountLifecycle()
	if err != nil {
		return fmt.Errorf("load account-lifecycle config: %w", err)
	}

	cleanupConfig, err := config.LoadCleanup()
	if err != nil {
		return fmt.Errorf("load cleanup config: %w", err)
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

	forgotPasswordLimiter, err := ratelimit.NewForgotPasswordLimiter(
		slidingWindowLimiter,
		rateLimitKeys,
		ratelimit.ForgotPasswordPolicy{
			IPLimit:     forgotPasswordConfig.RateLimit.IPLimit,
			IPWindow:    forgotPasswordConfig.RateLimit.IPWindow,
			EmailLimit:  forgotPasswordConfig.RateLimit.EmailLimit,
			EmailWindow: forgotPasswordConfig.RateLimit.EmailWindow,
		},
	)
	if err != nil {
		return fmt.Errorf("create forgot-password rate limiter: %w", err)
	}

	resetPasswordLimiter, err := ratelimit.NewResetPasswordLimiter(
		slidingWindowLimiter,
		rateLimitKeys,
		ratelimit.ResetPasswordPolicy{
			IPLimit:  resetPasswordConfig.IPLimit,
			IPWindow: resetPasswordConfig.IPWindow,
		},
	)
	if err != nil {
		return fmt.Errorf("create reset-password rate limiter: %w", err)
	}

	changePasswordLimiter, err := ratelimit.NewChangePasswordLimiter(
		slidingWindowLimiter,
		rateLimitKeys,
		ratelimit.ChangePasswordPolicy{
			IPLimit:        changePasswordConfig.IPLimit,
			IPWindow:       changePasswordConfig.IPWindow,
			IdentityLimit:  changePasswordConfig.IdentityLimit,
			IdentityWindow: changePasswordConfig.IdentityWindow,
		},
	)
	if err != nil {
		return fmt.Errorf("create change-password rate limiter: %w", err)
	}

	deleteAccountLimiter, err := ratelimit.NewDeleteAccountLimiter(
		slidingWindowLimiter,
		rateLimitKeys,
		ratelimit.DeleteAccountPolicy{
			IPLimit:        accountLifecycleConfig.DeleteAccount.IPLimit,
			IPWindow:       accountLifecycleConfig.DeleteAccount.IPWindow,
			IdentityLimit:  accountLifecycleConfig.DeleteAccount.IdentityLimit,
			IdentityWindow: accountLifecycleConfig.DeleteAccount.IdentityWindow,
		},
	)
	if err != nil {
		return fmt.Errorf("create delete-account rate limiter: %w", err)
	}

	reactivationLimiter, err := ratelimit.NewReactivationLimiter(
		slidingWindowLimiter,
		rateLimitKeys,
		ratelimit.ReactivationPolicy{
			IPLimit:     accountLifecycleConfig.Reactivation.IPLimit,
			IPWindow:    accountLifecycleConfig.Reactivation.IPWindow,
			EmailLimit:  accountLifecycleConfig.Reactivation.EmailLimit,
			EmailWindow: accountLifecycleConfig.Reactivation.EmailWindow,
		},
	)
	if err != nil {
		return fmt.Errorf("create reactivation rate limiter: %w", err)
	}

	signupRepository, err := postgres.NewSignupRepository(database)
	if err != nil {
		return fmt.Errorf("create signup repository: %w", err)
	}

	privilegedIdentityRepository, err :=
		postgres.NewPrivilegedIdentityRepository(database)
	if err != nil {
		return fmt.Errorf(
			"create privileged identity repository: %w",
			err,
		)
	}

	loginRepository, err := postgres.NewLoginRepository(database)
	if err != nil {
		return fmt.Errorf("create login repository: %w", err)
	}

	refreshRepository, err := postgres.NewRefreshRepository(database)
	if err != nil {
		return fmt.Errorf("create refresh repository: %w", err)
	}

	meRepository, err := postgres.NewMeRepository(database)
	if err != nil {
		return fmt.Errorf("create me repository: %w", err)
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

	forgotPasswordRepository, err := postgres.NewForgotPasswordRepository(database)
	if err != nil {
		return fmt.Errorf("create forgot-password repository: %w", err)
	}

	resetPasswordRepository, err := postgres.NewResetPasswordRepository(database)
	if err != nil {
		return fmt.Errorf("create reset-password repository: %w", err)
	}

	changePasswordRepository, err := postgres.NewChangePasswordRepository(database)
	if err != nil {
		return fmt.Errorf("create change-password repository: %w", err)
	}

	deleteAccountRepository, err := postgres.NewDeleteAccountRepository(database)
	if err != nil {
		return fmt.Errorf("create delete-account repository: %w", err)
	}

	reactivationRepository, err := postgres.NewReactivationRepository(database)
	if err != nil {
		return fmt.Errorf("create reactivation repository: %w", err)
	}

	loginHistoryRepository, err := postgres.NewLoginHistoryRepository(database)
	if err != nil {
		return fmt.Errorf("create login-history repository: %w", err)
	}

	cleanupRepository, err := postgres.NewCleanupRepository(database)
	if err != nil {
		return fmt.Errorf("create cleanup repository: %w", err)
	}

	passwordHasher := passwordhash.New()
	identifierGenerator := idgen.NewUUIDV7()

	dummyPasswordHash, err := passwordHasher.Hash(dummyLoginPassword)
	if err != nil {
		return fmt.Errorf("create dummy login password hash: %w", err)
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

	privilegedIdentityUseCase, err := createidentityapp.New(
		privilegedIdentityRepository,
		passwordHasher,
		identifierGenerator,
		identifierGenerator,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf(
			"create privileged identity use case: %w",
			err,
		)
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

	refreshUseCase, err := refreshapp.New(
		refreshRepository,
		refreshTokenCodec,
		accessTokenService,
		sessionStore,
		identifierGenerator,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create refresh use case: %w", err)
	}

	authenticateUseCase, err := authenticateapp.New(
		accessTokenService,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create authentication use case: %w", err)
	}

	meUseCase, err := getmeapp.New(meRepository)
	if err != nil {
		return fmt.Errorf("create get-me use case: %w", err)
	}

	sessionManagementService, err := sessionmanagementapp.New(sessionStore)
	if err != nil {
		return fmt.Errorf("create session-management service: %w", err)
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

	forgotPasswordUseCase, err := forgotpasswordapp.New(
		forgotPasswordRepository,
		identifierGenerator,
		forgotPasswordLimiter,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create forgot-password use case: %w", err)
	}

	resetPasswordUseCase, err := resetpasswordapp.New(
		resetPasswordRepository,
		passwordHasher,
		resetPasswordLimiter,
		sessionStore,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create reset-password use case: %w", err)
	}

	changePasswordUseCase, err := changepasswordapp.New(
		changePasswordRepository,
		passwordHasher,
		changePasswordLimiter,
		sessionStore,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create change-password use case: %w", err)
	}

	deleteAccountUseCase, err := deleteaccountapp.New(
		deleteAccountRepository,
		passwordHasher,
		deleteAccountLimiter,
		sessionStore,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create delete-account use case: %w", err)
	}

	reactivationUseCase, err := requestreactivationapp.New(
		reactivationRepository,
		passwordHasher,
		identifierGenerator,
		reactivationLimiter,
		dummyPasswordHash,
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create reactivation use case: %w", err)
	}

	loginHistoryUseCase, err := loginhistoryapp.New(loginHistoryRepository)
	if err != nil {
		return fmt.Errorf("create login-history use case: %w", err)
	}

	emailCatalog, err := emaildelivery.NewCatalog()
	if err != nil {
		return fmt.Errorf("create email translation catalog: %w", err)
	}

	passwordResetCatalog, err := emaildelivery.NewPasswordResetCatalog()
	if err != nil {
		return fmt.Errorf("create password-reset translation catalog: %w", err)
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
		emailCatalog,
		cfg.Email.VerificationURL,
	)
	if err != nil {
		return fmt.Errorf("create verification mailer: %w", err)
	}

	passwordResetMailer, err := emaildelivery.NewPasswordResetMailer(
		smtpSender,
		emailRenderer,
		passwordResetCatalog,
		forgotPasswordConfig.PasswordResetURL,
	)
	if err != nil {
		return fmt.Errorf("create password-reset mailer: %w", err)
	}

	outboxRepository, err := postgres.NewOutboxRepository(database)
	if err != nil {
		return fmt.Errorf("create outbox repository: %w", err)
	}

	outboxWorker, err := outboxapp.NewWorker(
		outboxRepository,
		verificationMailer,
		passwordResetMailer,
		sessionStore,
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

	cleanupWorker, err := cleanupapp.NewWorker(
		cleanupRepository,
		logger,
		cleanupapp.Config{
			Interval:              cleanupConfig.Interval,
			DatabaseTimeout:       cleanupConfig.DatabaseTimeout,
			BatchSize:             cleanupConfig.BatchSize,
			LoginAttemptRetention: cleanupConfig.LoginAttemptRetention,
			TokenRetention:        cleanupConfig.TokenRetention,
			OutboxRetention:       cleanupConfig.OutboxRetention,
		},
		time.Now,
	)
	if err != nil {
		return fmt.Errorf("create cleanup worker: %w", err)
	}

	handler := httpapi.NewRouter(
		logger,
		database,
		cache,
		httpapi.RouterDependencies{
			Signup:                   signupUseCase,
			Login:                    loginUseCase,
			Refresh:                  refreshUseCase,
			VerifyEmail:              verifyEmailUseCase,
			ResendVerification:       resendVerificationUseCase,
			ForgotPassword:           forgotPasswordUseCase,
			ResetPassword:            resetPasswordUseCase,
			ChangePassword:           changePasswordUseCase,
			Me:                       meUseCase,
			CreatePrivilegedIdentity: privilegedIdentityUseCase,
			Reactivation:             reactivationUseCase,
			DeleteAccount:            deleteAccountUseCase,
			LoginHistory:             loginHistoryUseCase,
			Authenticator:            authenticateUseCase,
			Sessions:                 sessionManagementService,
			JWKS:                     accessTokenService,
		},
	)

	server := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		outboxWorker.Run(applicationContext)
	}()
	go func() {
		defer workers.Done()
		cleanupWorker.Run(applicationContext)
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

	workersDone := make(chan struct{})
	go func() {
		workers.Wait()
		close(workersDone)
	}()

	workerShutdownTimer := time.NewTimer(cfg.HTTP.ShutdownTimeout)
	defer workerShutdownTimer.Stop()

	select {
	case <-workersDone:
		logger.Info("background workers stopped gracefully")

	case <-workerShutdownTimer.C:
		runErr = errors.Join(
			runErr,
			errors.New("background worker shutdown timed out"),
		)
	}

	logger.Info("http server stopped gracefully")
	return runErr
}

func newAccessTokenService(
	tokenConfig config.TokenConfig,
) (*accesstoken.RS256, error) {
	privateKey, err := accesstoken.LoadPrivateKey(tokenConfig.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load access-token private key: %w", err)
	}

	service, err := accesstoken.New(
		privateKey,
		accesstoken.Config{
			Issuer:           tokenConfig.Issuer,
			Audience:         tokenConfig.Audience,
			KeyID:            tokenConfig.KeyID,
			AccessTokenTTL:   tokenConfig.AccessTokenTTL,
			AllowedClockSkew: tokenConfig.AllowedClockSkew,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create access-token service: %w", err)
	}

	return service, nil
}
