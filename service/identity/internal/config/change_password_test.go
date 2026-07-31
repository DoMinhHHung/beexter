package config

import (
	"testing"
	"time"
)

func TestLoadChangePasswordDefaults(t *testing.T) {
	t.Setenv("CHANGE_PASSWORD_RATE_LIMIT_IP_REQUESTS", "")
	t.Setenv("CHANGE_PASSWORD_RATE_LIMIT_IP_WINDOW", "")
	t.Setenv("CHANGE_PASSWORD_RATE_LIMIT_IDENTITY_REQUESTS", "")
	t.Setenv("CHANGE_PASSWORD_RATE_LIMIT_IDENTITY_WINDOW", "")

	config, err := LoadChangePassword()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if config.IPLimit != 5 || config.IPWindow != 15*time.Minute {
		t.Fatalf("unexpected IP policy: %+v", config)
	}
	if config.IdentityLimit != 5 || config.IdentityWindow != time.Hour {
		t.Fatalf("unexpected identity policy: %+v", config)
	}
}
