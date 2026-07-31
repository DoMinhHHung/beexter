package config

import (
	"testing"
	"time"
)

func TestLoadAccountLifecycleDefaults(t *testing.T) {
	for _, key := range []string{
		"DELETE_ACCOUNT_RATE_LIMIT_IP_REQUESTS",
		"DELETE_ACCOUNT_RATE_LIMIT_IP_WINDOW",
		"DELETE_ACCOUNT_RATE_LIMIT_IDENTITY_REQUESTS",
		"DELETE_ACCOUNT_RATE_LIMIT_IDENTITY_WINDOW",
		"REACTIVATION_RATE_LIMIT_IP_REQUESTS",
		"REACTIVATION_RATE_LIMIT_IP_WINDOW",
		"REACTIVATION_RATE_LIMIT_EMAIL_REQUESTS",
		"REACTIVATION_RATE_LIMIT_EMAIL_WINDOW",
	} {
		t.Setenv(key, "")
	}
	config, err := LoadAccountLifecycle()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.DeleteAccount.IPLimit != 3 ||
		config.DeleteAccount.IdentityWindow != time.Hour ||
		config.Reactivation.EmailLimit != 3 {
		t.Fatalf("unexpected defaults: %+v", config)
	}
}
