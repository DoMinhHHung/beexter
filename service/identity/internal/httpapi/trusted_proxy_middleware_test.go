package httpapi

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	appsignup "github.com/DoMinhHHung/beexster/service/identity/internal/application/signup"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
)

func TestTrustedProxyMiddlewareDefaultsToPeerAddress(t *testing.T) {
	t.Parallel()

	var observedRemoteAddr string
	handler := trustedProxyMiddleware(
		nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			observedRemoteAddr = r.RemoteAddr
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	request.RemoteAddr = "192.0.2.10:54321"
	request.Header.Set("X-Forwarded-For", "198.51.100.50")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if observedRemoteAddr != "192.0.2.10:54321" {
		t.Fatalf("expected unchanged peer address, got %q", observedRemoteAddr)
	}
}

func TestTrustedProxyMiddlewareIgnoresHeaderFromUntrustedPeer(t *testing.T) {
	t.Parallel()

	assertResolvedRemoteAddr(
		t,
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		"192.0.2.10:54321",
		[]string{"198.51.100.50"},
		"192.0.2.10:54321",
	)
}

func TestTrustedProxyMiddlewareChoosesNearestUntrustedHop(t *testing.T) {
	t.Parallel()

	assertResolvedRemoteAddr(
		t,
		[]netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("192.0.2.0/24"),
		},
		"10.0.0.2:54321",
		[]string{"198.51.100.77, 203.0.113.9, 192.0.2.25"},
		"203.0.113.9",
	)
}

func TestTrustedProxyMiddlewareSupportsMultipleForwardedHeaderLines(t *testing.T) {
	t.Parallel()

	assertResolvedRemoteAddr(
		t,
		[]netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("192.0.2.0/24"),
		},
		"10.0.0.2:54321",
		[]string{"198.51.100.77", "192.0.2.25"},
		"198.51.100.77",
	)
}

func TestTrustedProxyMiddlewareFailsClosedOnMalformedHeader(t *testing.T) {
	t.Parallel()

	for _, header := range []string{
		"not-an-ip",
		"198.51.100.77,",
		"198.51.100.77, unknown, 192.0.2.25",
	} {
		header := header
		t.Run(header, func(t *testing.T) {
			t.Parallel()

			assertResolvedRemoteAddr(
				t,
				[]netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
					netip.MustParsePrefix("192.0.2.0/24"),
				},
				"10.0.0.2:54321",
				[]string{header},
				"10.0.0.2:54321",
			)
		})
	}
}

func TestTrustedProxyMiddlewareFailsClosedWhenAllHopsAreTrusted(t *testing.T) {
	t.Parallel()

	assertResolvedRemoteAddr(
		t,
		[]netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("192.0.2.0/24"),
		},
		"10.0.0.2:54321",
		[]string{"192.0.2.30, 192.0.2.25"},
		"10.0.0.2:54321",
	)
}

func TestTrustedProxyMiddlewareMakesResolvedIPVisibleToAccessLog(t *testing.T) {
	t.Parallel()

	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
	handler := trustedProxyMiddleware(
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		applyMiddleware(
			logger,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RemoteAddr != "198.51.100.50" {
					t.Fatalf("expected resolved handler IP, got %q", r.RemoteAddr)
				}
				w.WriteHeader(http.StatusNoContent)
			}),
		),
	)

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	request.RemoteAddr = "10.0.0.2:54321"
	request.Header.Set("X-Forwarded-For", "198.51.100.50")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if !strings.Contains(
		logOutput.String(),
		`"remote_ip":"198.51.100.50"`,
	) {
		t.Fatalf("expected resolved IP in access log, got %s", logOutput.String())
	}
}

func TestRouterPassesResolvedIPToHandlerInput(t *testing.T) {
	t.Parallel()

	executor := &stubSignupExecutor{execute: func(
		_ context.Context,
		input appsignup.Input,
	) (appsignup.Output, error) {
		if input.IPAddress.String() != "198.51.100.50" {
			t.Fatalf("expected resolved application IP, got %s", input.IPAddress)
		}

		return appsignup.Output{
			ID:    identity.ID("0198f124-659f-7cbd-a441-dc7eea175073"),
			Email: "user@example.com",
		}, nil
	}}
	handler := NewRouter(
		testLogger(),
		nil,
		nil,
		RouterDependencies{
			Signup: executor,
			TrustedProxyPrefixes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
			},
		},
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/signup",
		strings.NewReader(`{"email":"user@example.com","password":"Secure1!"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", "198.51.100.50")
	request.RemoteAddr = "10.0.0.2:54321"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusCreated,
			response.Code,
			response.Body.String(),
		)
	}
}

func assertResolvedRemoteAddr(
	t *testing.T,
	trustedProxyPrefixes []netip.Prefix,
	peer string,
	forwardedHeaderValues []string,
	expected string,
) {
	t.Helper()

	var observedRemoteAddr string
	handler := trustedProxyMiddleware(
		trustedProxyPrefixes,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			observedRemoteAddr = r.RemoteAddr
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	request.RemoteAddr = peer
	request.Header.Del("X-Forwarded-For")
	for _, value := range forwardedHeaderValues {
		request.Header.Add("X-Forwarded-For", value)
	}

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if observedRemoteAddr != expected {
		t.Fatalf("expected resolved remote address %q, got %q", expected, observedRemoteAddr)
	}
}
