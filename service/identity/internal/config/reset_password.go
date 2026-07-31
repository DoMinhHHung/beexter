package config

import "time"

const (
	defaultResetPasswordIPLimit  = 5
	defaultResetPasswordIPWindow = 15 * time.Minute
)

type ResetPasswordConfig struct {
	IPLimit  int64
	IPWindow time.Duration
}

func LoadResetPassword() (ResetPasswordConfig, error) {
	ipLimit, err := readPositiveInt(
		"RESET_PASSWORD_RATE_LIMIT_IP_REQUESTS",
		defaultResetPasswordIPLimit,
	)
	if err != nil {
		return ResetPasswordConfig{}, err
	}

	ipWindow, err := readPositiveDuration(
		"RESET_PASSWORD_RATE_LIMIT_IP_WINDOW",
		defaultResetPasswordIPWindow,
	)
	if err != nil {
		return ResetPasswordConfig{}, err
	}

	return ResetPasswordConfig{
		IPLimit:  int64(ipLimit),
		IPWindow: ipWindow,
	}, nil
}
