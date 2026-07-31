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
		len(configuration.AdditionalPublicKeys) != 0 ||
		configuration.AccessTokenTTL != 15*time.Minute ||
		configuration.AllowedClockSkew != 30*time.Second ||
		configuration.RefreshSecret != strings.Repeat("r", 32) {
		t.Fatalf("unexpected token config: %+v", configuration)
	}
}

func TestLoadTokenConfigParsesAdditionalPublicKeys(t *testing.T) {
	setValidTokenEnvironment(t)
	t.Setenv(
		"JWT_ADDITIONAL_PUBLIC_KEYS",
		`[
			{"kid":" old-z ","public_key_path":" ./keys/old-z.pem "},
			{"kid":"old-a","public_key_path":"./keys/old-a.pem"}
		]`,
	)

	configuration, err := loadTokenConfig()
	if err != nil {
		t.Fatalf("load token config: %v", err)
	}
	if len(configuration.AdditionalPublicKeys) != 2 {
		t.Fatalf(
			"additional public key count = %d, want 2",
			len(configuration.AdditionalPublicKeys),
		)
	}
	if configuration.AdditionalPublicKeys[0].KeyID != "old-z" ||
		configuration.AdditionalPublicKeys[0].PublicKeyPath != "./keys/old-z.pem" ||
		configuration.AdditionalPublicKeys[1].KeyID != "old-a" ||
		configuration.AdditionalPublicKeys[1].PublicKeyPath != "./keys/old-a.pem" {
		t.Fatalf(
			"unexpected additional public keys: %+v",
			configuration.AdditionalPublicKeys,
		)
	}
}

func TestLoadTokenConfigAcceptsEmptyAdditionalPublicKeyArray(t *testing.T) {
	setValidTokenEnvironment(t)
	t.Setenv("JWT_ADDITIONAL_PUBLIC_KEYS", "[]")

	configuration, err := loadTokenConfig()
	if err != nil {
		t.Fatalf("load token config: %v", err)
	}
	if configuration.AdditionalPublicKeys == nil ||
		len(configuration.AdditionalPublicKeys) != 0 {
		t.Fatalf(
			"unexpected empty additional key config: %#v",
			configuration.AdditionalPublicKeys,
		)
	}
}

func TestLoadTokenConfigRejectsInvalidAdditionalPublicKeys(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "malformed JSON", value: `[{`},
		{name: "null", value: `null`},
		{name: "object instead of array", value: `{}`},
		{name: "unknown field", value: `[{"kid":"old","public_key_path":"old.pem","private_key_path":"secret.pem"}]`},
		{name: "trailing JSON", value: `[] {}`},
		{name: "missing kid", value: `[{"public_key_path":"old.pem"}]`},
		{name: "missing path", value: `[{"kid":"old"}]`},
		{name: "blank fields", value: `[{"kid":" ","public_key_path":" \t "}]`},
		{name: "active collision", value: `[{"kid":"identity-2026-01","public_key_path":"old.pem"}]`},
		{name: "trimmed active collision", value: `[{"kid":" identity-2026-01 ","public_key_path":"old.pem"}]`},
		{name: "duplicate kid", value: `[{"kid":"old","public_key_path":"old-1.pem"},{"kid":" old ","public_key_path":"old-2.pem"}]`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setValidTokenEnvironment(t)
			t.Setenv("JWT_ADDITIONAL_PUBLIC_KEYS", test.value)

			if _, err := loadTokenConfig(); err == nil {
				t.Fatal("expected additional public-key validation error")
			}
		})
	}
}

func TestLoadTokenConfigErrorsDoNotExposeAdditionalKeyInput(t *testing.T) {
	setValidTokenEnvironment(t)
	const sensitiveMarker = "sensitive-path-marker"
	t.Setenv(
		"JWT_ADDITIONAL_PUBLIC_KEYS",
		`[{"kid":"identity-2026-01","public_key_path":"`+
			sensitiveMarker+`"}]`,
	)

	_, err := loadTokenConfig()
	if err == nil {
		t.Fatal("expected duplicate key ID error")
	}
	if strings.Contains(err.Error(), sensitiveMarker) {
		t.Fatalf("error exposed configured public-key input: %v", err)
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
	t.Setenv("JWT_ADDITIONAL_PUBLIC_KEYS", "")
	t.Setenv("ACCESS_TOKEN_TTL", "")
	t.Setenv("JWT_ALLOWED_CLOCK_SKEW", "")
	t.Setenv("REFRESH_TOKEN_SECRET", strings.Repeat("r", 32))
}
