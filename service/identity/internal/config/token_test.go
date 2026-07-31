package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadTokenConfigDefaults(t *testing.T) {
	setValidTokenEnvironment(t)

	configuration, err := loadTokenConfig()
	if err != nil {
		t.Fatalf("load token config: %v", err)
	}

	if configuration.Issuer != "https://identity.example.test" ||
		configuration.Audience != "beexster-services" ||
		configuration.KeyID != "identity-2026-01" ||
		configuration.PrivateKeyPath != "./dev-private.pem" ||
		configuration.AccessTokenTTL != 15*time.Minute ||
		configuration.AllowedClockSkew != 30*time.Second ||
		configuration.RefreshSecret != strings.Repeat("r", 32) {
		t.Fatalf("unexpected token config: %+v", configuration)
	}
}

func TestLoadTokenConfigRequiresTrimmedJWTValues(t *testing.T) {
	requiredKeys := []string{
		"JWT_ISSUER",
		"JWT_AUDIENCE",
		"JWT_KEY_ID",
		"JWT_PRIVATE_KEY_PATH",
	}

	for _, key := range requiredKeys {
		key := key
		t.Run(key, func(t *testing.T) {
			setValidTokenEnvironment(t)
			t.Setenv(key, " \t ")

			if _, err := loadTokenConfig(); err == nil {
				t.Fatalf("expected %s validation error", key)
			}
		})
	}
}

func TestLoadTokenConfigValidatesAccessTokenTTL(t *testing.T) {
	for _, value := range []string{"0s", "-1s", "1h1s"} {
		value := value
		t.Run(value, func(t *testing.T) {
			setValidTokenEnvironment(t)
			t.Setenv("ACCESS_TOKEN_TTL", value)

			if _, err := loadTokenConfig(); err == nil {
				t.Fatalf("expected ACCESS_TOKEN_TTL %q to fail", value)
			}
		})
	}
}

func TestLoadTokenConfigValidatesAllowedClockSkew(t *testing.T) {
	for _, value := range []string{"-1s", "2m1s"} {
		value := value
		t.Run(value, func(t *testing.T) {
			setValidTokenEnvironment(t)
			t.Setenv("JWT_ALLOWED_CLOCK_SKEW", value)

			if _, err := loadTokenConfig(); err == nil {
				t.Fatalf("expected JWT_ALLOWED_CLOCK_SKEW %q to fail", value)
			}
		})
	}
}

func TestLoadTokenConfigAllowsZeroClockSkewAndOneHourTTL(t *testing.T) {
	setValidTokenEnvironment(t)
	t.Setenv("ACCESS_TOKEN_TTL", "1h")
	t.Setenv("JWT_ALLOWED_CLOCK_SKEW", "0s")

	configuration, err := loadTokenConfig()
	if err != nil {
		t.Fatalf("load token config: %v", err)
	}
	if configuration.AccessTokenTTL != time.Hour ||
		configuration.AllowedClockSkew != 0 {
		t.Fatalf("unexpected duration boundaries: %+v", configuration)
	}
}

func setValidTokenEnvironment(t *testing.T) {
	t.Helper()

	t.Setenv("JWT_ISSUER", " https://identity.example.test ")
	t.Setenv("JWT_AUDIENCE", " beexster-services ")
	t.Setenv("JWT_KEY_ID", " identity-2026-01 ")
	t.Setenv("JWT_PRIVATE_KEY_PATH", " ./dev-private.pem ")
	t.Setenv("ACCESS_TOKEN_TTL", "")
	t.Setenv("JWT_ALLOWED_CLOCK_SKEW", "")
	t.Setenv("REFRESH_TOKEN_SECRET", strings.Repeat("r", 32))
}
