package config

import "time"

const (
	defaultForgotPasswordIPLimit     = 5
	defaultForgotPasswordIPWindow    = 15 * time.Minute
	defaultForgotPasswordEmailLimit  = 3
	defaultForgotPasswordEmailWindow = time.Hour
)

type ForgotPasswordConfig struct {
	RateLimit        EmailIPRateLimitConfig
	PasswordResetURL string
}

func LoadForgotPassword() (ForgotPasswordConfig, error) {
	rateLimit, err := loadEmailIPRateLimit(
		"FORGOT_PASSWORD_RATE_LIMIT",
		defaultForgotPasswordIPLimit,
		defaultForgotPasswordIPWindow,
		defaultForgotPasswordEmailLimit,
		defaultForgotPasswordEmailWindow,
	)
	if err != nil {
		return ForgotPasswordConfig{}, err
	}

	passwordResetURL, err := requiredString("PASSWORD_RESET_URL")
	if err != nil {
		return ForgotPasswordConfig{}, err
	}

	return ForgotPasswordConfig{
		RateLimit:        rateLimit,
		PasswordResetURL: passwordResetURL,
	}, nil
}
