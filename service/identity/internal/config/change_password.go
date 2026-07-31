package config

import "time"

const (
	defaultChangePasswordIPLimit        = 5
	defaultChangePasswordIPWindow       = 15 * time.Minute
	defaultChangePasswordIdentityLimit  = 5
	defaultChangePasswordIdentityWindow = time.Hour
)

type ChangePasswordConfig struct {
	IPLimit        int64
	IPWindow       time.Duration
	IdentityLimit  int64
	IdentityWindow time.Duration
}

func LoadChangePassword() (ChangePasswordConfig, error) {
	ipLimit, err := readPositiveInt(
		"CHANGE_PASSWORD_RATE_LIMIT_IP_REQUESTS",
		defaultChangePasswordIPLimit,
	)
	if err != nil {
		return ChangePasswordConfig{}, err
	}
	ipWindow, err := readPositiveDuration(
		"CHANGE_PASSWORD_RATE_LIMIT_IP_WINDOW",
		defaultChangePasswordIPWindow,
	)
	if err != nil {
		return ChangePasswordConfig{}, err
	}
	identityLimit, err := readPositiveInt(
		"CHANGE_PASSWORD_RATE_LIMIT_IDENTITY_REQUESTS",
		defaultChangePasswordIdentityLimit,
	)
	if err != nil {
		return ChangePasswordConfig{}, err
	}
	identityWindow, err := readPositiveDuration(
		"CHANGE_PASSWORD_RATE_LIMIT_IDENTITY_WINDOW",
		defaultChangePasswordIdentityWindow,
	)
	if err != nil {
		return ChangePasswordConfig{}, err
	}

	return ChangePasswordConfig{
		IPLimit:        int64(ipLimit),
		IPWindow:       ipWindow,
		IdentityLimit:  int64(identityLimit),
		IdentityWindow: identityWindow,
	}, nil
}
