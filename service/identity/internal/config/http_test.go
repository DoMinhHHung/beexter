package config

import (
	"net/netip"
	"testing"
	"time"
)

func TestLoadHTTPConfigDefaultsToNoTrustedProxies(t *testing.T) {
	t.Setenv("HTTP_PORT", "")
	t.Setenv("HTTP_SHUTDOWN_TIMEOUT", "")
	t.Setenv("HTTP_TRUSTED_PROXY_CIDRS", "")

	configuration, err := loadHTTPConfig()
	if err != nil {
		t.Fatalf("load HTTP config: %v", err)
	}

	if configuration.Addr != ":8080" ||
		configuration.ShutdownTimeout != 10*time.Second {
		t.Fatalf("unexpected HTTP defaults: %+v", configuration)
	}

	if len(configuration.TrustedProxyPrefixes) != 0 {
		t.Fatalf(
			"expected no trusted proxies by default, got %v",
			configuration.TrustedProxyPrefixes,
		)
	}
}

func TestLoadHTTPConfigParsesAndMasksTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("HTTP_PORT", "8443")
	t.Setenv("HTTP_SHUTDOWN_TIMEOUT", "20s")
	t.Setenv(
		"HTTP_TRUSTED_PROXY_CIDRS",
		" 10.20.30.40/8, 2001:db8:1234::1/32 ",
	)

	configuration, err := loadHTTPConfig()
	if err != nil {
		t.Fatalf("load HTTP config: %v", err)
	}

	expected := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if len(configuration.TrustedProxyPrefixes) != len(expected) {
		t.Fatalf(
			"expected %d trusted prefixes, got %v",
			len(expected),
			configuration.TrustedProxyPrefixes,
		)
	}

	for index := range expected {
		if configuration.TrustedProxyPrefixes[index] != expected[index] {
			t.Fatalf(
				"expected prefix %s at index %d, got %s",
				expected[index],
				index,
				configuration.TrustedProxyPrefixes[index],
			)
		}
	}
}

func TestLoadHTTPConfigRejectsInvalidTrustedProxyCIDRs(t *testing.T) {
	testCases := []string{
		"192.0.2.10",
		"not-a-cidr",
		"10.0.0.0/8,,192.0.2.0/24",
	}

	for _, value := range testCases {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Setenv("HTTP_PORT", "")
			t.Setenv("HTTP_SHUTDOWN_TIMEOUT", "")
			t.Setenv("HTTP_TRUSTED_PROXY_CIDRS", value)

			if _, err := loadHTTPConfig(); err == nil {
				t.Fatalf(
					"expected HTTP_TRUSTED_PROXY_CIDRS %q to fail",
					value,
				)
			}
		})
	}
}
