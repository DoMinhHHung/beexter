package config

import "time"

const (
	defaultDeleteAccountIPLimit        = 3
	defaultDeleteAccountIPWindow       = time.Hour
	defaultDeleteAccountIdentityLimit  = 3
	defaultDeleteAccountIdentityWindow = time.Hour

	defaultReactivationIPLimit     = 5
	defaultReactivationIPWindow    = 15 * time.Minute
	defaultReactivationEmailLimit  = 3
	defaultReactivationEmailWindow = time.Hour
)

type AccountLifecycleConfig struct {
	DeleteAccount DeleteAccountRateLimitConfig
	Reactivation  EmailIPRateLimitConfig
}

type DeleteAccountRateLimitConfig struct {
	IPLimit        int64
	IPWindow       time.Duration
	IdentityLimit  int64
	IdentityWindow time.Duration
}

func LoadAccountLifecycle() (AccountLifecycleConfig, error) {
	deleteIPLimit, err := readPositiveInt(
		"DELETE_ACCOUNT_RATE_LIMIT_IP_REQUESTS",
		defaultDeleteAccountIPLimit,
	)
	if err != nil {
		return AccountLifecycleConfig{}, err
	}
	deleteIPWindow, err := readPositiveDuration(
		"DELETE_ACCOUNT_RATE_LIMIT_IP_WINDOW",
		defaultDeleteAccountIPWindow,
	)
	if err != nil {
		return AccountLifecycleConfig{}, err
	}
	deleteIdentityLimit, err := readPositiveInt(
		"DELETE_ACCOUNT_RATE_LIMIT_IDENTITY_REQUESTS",
		defaultDeleteAccountIdentityLimit,
	)
	if err != nil {
		return AccountLifecycleConfig{}, err
	}
	deleteIdentityWindow, err := readPositiveDuration(
		"DELETE_ACCOUNT_RATE_LIMIT_IDENTITY_WINDOW",
		defaultDeleteAccountIdentityWindow,
	)
	if err != nil {
		return AccountLifecycleConfig{}, err
	}

	reactivation, err := loadEmailIPRateLimit(
		"REACTIVATION_RATE_LIMIT",
		defaultReactivationIPLimit,
		defaultReactivationIPWindow,
		defaultReactivationEmailLimit,
		defaultReactivationEmailWindow,
	)
	if err != nil {
		return AccountLifecycleConfig{}, err
	}

	return AccountLifecycleConfig{
		DeleteAccount: DeleteAccountRateLimitConfig{
			IPLimit:        int64(deleteIPLimit),
			IPWindow:       deleteIPWindow,
			IdentityLimit:  int64(deleteIdentityLimit),
			IdentityWindow: deleteIdentityWindow,
		},
		Reactivation: reactivation,
	}, nil
}
