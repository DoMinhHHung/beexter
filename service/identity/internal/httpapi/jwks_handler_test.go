package httpapi

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DoMinhHHung/beexster/service/identity/internal/platform/accesstoken"
)

func TestJWKSEndpointIsUnauthenticated(t *testing.T) {
	t.Parallel()

	provider := stubJWKSProvider{document: testJWKS()}
	handler := NewRouter(
		testLogger(),
		nil,
		nil,
		RouterDependencies{JWKS: provider},
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected Content-Type %q", response.Header().Get("Content-Type"))
	}
	if response.Header().Get("Cache-Control") != jwksCacheControl {
		t.Fatalf("unexpected Cache-Control %q", response.Header().Get("Cache-Control"))
	}
	if response.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("JWKS endpoint must not require bearer authentication")
	}

	assertPublicJWKS(t, response.Body.Bytes())
}

func TestJWKSHandlerOutputIsDeterministic(t *testing.T) {
	t.Parallel()

	handler := applyMiddleware(
		testLogger(),
		jwksHandler(testLogger(), stubJWKSProvider{document: testJWKS()}),
	)
	first := httptest.NewRecorder()
	second := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatalf("JWKS output is not deterministic: %q != %q", first.Body, second.Body)
	}
}

func TestJWKSHandlerKeyMatchesSigner(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	provider, err := accesstoken.New(privateKey, accesstoken.Config{
		Issuer:           "https://identity.example.com",
		Audience:         "beexster-services",
		KeyID:            "identity-key-2026-01",
		AccessTokenTTL:   15 * time.Minute,
		AllowedClockSkew: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("create access-token service: %v", err)
	}

	response := httptest.NewRecorder()
	jwksHandler(testLogger(), provider).ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil),
	)

	var document accesstoken.JWKS
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(document.Keys) != 1 {
		t.Fatalf("expected exactly one JWK, got %d", len(document.Keys))
	}

	modulus, err := base64.RawURLEncoding.DecodeString(document.Keys[0].Modulus)
	if err != nil {
		t.Fatalf("decode JWK modulus: %v", err)
	}
	if !bytes.Equal(modulus, privateKey.PublicKey.N.Bytes()) {
		t.Fatal("JWK modulus does not match signer public key")
	}

	exponent, err := base64.RawURLEncoding.DecodeString(document.Keys[0].Exponent)
	if err != nil {
		t.Fatalf("decode JWK exponent: %v", err)
	}
	if new(big.Int).SetBytes(exponent).Cmp(big.NewInt(int64(privateKey.PublicKey.E))) != 0 {
		t.Fatal("JWK exponent does not match signer public key")
	}
}

func assertPublicJWKS(t *testing.T, raw []byte) {
	t.Helper()

	var document map[string][]map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	keys := document["keys"]
	if len(keys) != 1 {
		t.Fatalf("expected exactly one JWK, got %d", len(keys))
	}

	key := keys[0]
	for name, expected := range map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": "identity-key-2026-01",
		"n":   "AQIDBA",
		"e":   "AQAB",
	} {
		if key[name] != expected {
			t.Fatalf("unexpected %s: %#v", name, key[name])
		}
	}

	for _, privateParameter := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, exists := key[privateParameter]; exists {
			t.Fatalf("JWKS exposes private parameter %q", privateParameter)
		}
	}
}

func testJWKS() accesstoken.JWKS {
	return accesstoken.JWKS{Keys: []accesstoken.JWK{{
		KeyType:   "RSA",
		Use:       "sig",
		Algorithm: "RS256",
		KeyID:     "identity-key-2026-01",
		Modulus:   "AQIDBA",
		Exponent:  "AQAB",
	}}}
}

type stubJWKSProvider struct {
	document accesstoken.JWKS
}

func (s stubJWKSProvider) JWKS() accesstoken.JWKS {
	return s.document
}
