package config

import (
	"testing"
	"time"
)

func TestLoadResetPasswordUsesDefaults(t *testing.T) {
	t.Setenv("RESET_PASSWORD_RATE_LIMIT_IP_REQUESTS", "")
	t.Setenv("RESET_PASSWORD_RATE_LIMIT_IP_WINDOW", "")

	config, err := LoadResetPassword()
	if err != nil {
		t.Fatalf("load reset-password config: %v", err)
	}

	if config.IPLimit != int64(defaultResetPasswordIPLimit) {
		t.Fatalf(
			"expected IP limit %d, got %d",
			defaultResetPasswordIPLimit,
			config.IPLimit,
		)
	}
	if config.IPWindow != defaultResetPasswordIPWindow {
		t.Fatalf(
			"expected IP window %s, got %s",
			defaultResetPasswordIPWindow,
			config.IPWindow,
		)
	}
}

func TestLoadResetPasswordRejectsInvalidWindow(t *testing.T) {
	t.Setenv("RESET_PASSWORD_RATE_LIMIT_IP_REQUESTS", "5")
	t.Setenv("RESET_PASSWORD_RATE_LIMIT_IP_WINDOW", "0s")

	_, err := LoadResetPassword()
	if err == nil {
		t.Fatal("expected reset-password config validation error")
	}
}

func TestLoadResetPasswordReadsOverrides(t *testing.T) {
	t.Setenv("RESET_PASSWORD_RATE_LIMIT_IP_REQUESTS", "7")
	t.Setenv("RESET_PASSWORD_RATE_LIMIT_IP_WINDOW", "30m")

	config, err := LoadResetPassword()
	if err != nil {
		t.Fatalf("load reset-password config: %v", err)
	}

	if config.IPLimit != 7 {
		t.Fatalf("expected IP limit 7, got %d", config.IPLimit)
	}
	if config.IPWindow != 30*time.Minute {
		t.Fatalf(
			"expected IP window %s, got %s",
			30*time.Minute,
			config.IPWindow,
		)
	}
}
