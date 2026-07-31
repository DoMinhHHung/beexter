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

func TestJWKSHandlerReturnsActiveKeyFirst(t *testing.T) {
	t.Parallel()

	activeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate active RSA key: %v", err)
	}
	previousKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate retained RSA key: %v", err)
	}
	provider, err := accesstoken.New(activeKey, accesstoken.Config{
		Issuer:           "https://identity.example.com",
		Audience:         "beexter-services",
		KeyID:            "identity-active-2026-08",
		AccessTokenTTL:   15 * time.Minute,
		AllowedClockSkew: 30 * time.Second,
		VerificationKeys: []accesstoken.VerificationKey{{
			KeyID:     "identity-previous-2026-07",
			PublicKey: &previousKey.PublicKey,
		}},
	})
	if err != nil {
		t.Fatalf("create multi-key access-token service: %v", err)
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
	if len(document.Keys) != 2 {
		t.Fatalf("expected active and retained JWKs, got %d", len(document.Keys))
	}
	if document.Keys[0].KeyID != "identity-active-2026-08" ||
		document.Keys[1].KeyID != "identity-previous-2026-07" {
		t.Fatalf("unexpected JWKS key order: %+v", document.Keys)
	}
	assertJWKMatchesPublicKey(t, document.Keys[0], &activeKey.PublicKey)
	assertJWKMatchesPublicKey(t, document.Keys[1], &previousKey.PublicKey)
}

func assertJWKMatchesPublicKey(
	t *testing.T,
	key accesstoken.JWK,
	publicKey *rsa.PublicKey,
) {
	t.Helper()

	modulus, err := base64.RawURLEncoding.DecodeString(key.Modulus)
	if err != nil {
		t.Fatalf("decode JWK modulus: %v", err)
	}
	if !bytes.Equal(modulus, publicKey.N.Bytes()) {
		t.Fatalf("JWK %q modulus does not match public key", key.KeyID)
	}

	exponent, err := base64.RawURLEncoding.DecodeString(key.Exponent)
	if err != nil {
		t.Fatalf("decode JWK exponent: %v", err)
	}
	if new(big.Int).SetBytes(exponent).Cmp(big.NewInt(int64(publicKey.E))) != 0 {
		t.Fatalf("JWK %q exponent does not match public key", key.KeyID)
	}
}

func assertPublicJWKS(t *testing.T, raw []byte) {
	t.Helper()

	var document map[string][]map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(document) != 1 {
		t.Fatalf("JWKS must contain only the keys member, got %#v", document)
	}
	keys := document["keys"]
	if len(keys) != 2 {
		t.Fatalf("expected active and retained JWKs, got %d", len(keys))
	}

	expectedKeys := []map[string]string{
		{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": "identity-active-2026-08",
			"n":   "AQIDBA",
			"e":   "AQAB",
		},
		{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": "identity-previous-2026-07",
			"n":   "BQYHCA",
			"e":   "AQAB",
		},
	}

	for index, key := range keys {
		if len(key) != len(expectedKeys[index]) {
			t.Fatalf("JWK %d has unexpected fields: %#v", index, key)
		}
		for name, expected := range expectedKeys[index] {
			if key[name] != expected {
				t.Fatalf("unexpected JWK %d %s: %#v", index, name, key[name])
			}
		}

		for _, privateParameter := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, exists := key[privateParameter]; exists {
				t.Fatalf(
					"JWK %d exposes private parameter %q",
					index,
					privateParameter,
				)
			}
		}
	}
}

func testJWKS() accesstoken.JWKS {
	return accesstoken.JWKS{Keys: []accesstoken.JWK{
		{
			KeyType:   "RSA",
			Use:       "sig",
			Algorithm: "RS256",
			KeyID:     "identity-active-2026-08",
			Modulus:   "AQIDBA",
			Exponent:  "AQAB",
		},
		{
			KeyType:   "RSA",
			Use:       "sig",
			Algorithm: "RS256",
			KeyID:     "identity-previous-2026-07",
			Modulus:   "BQYHCA",
			Exponent:  "AQAB",
		},
	}}
}

type stubJWKSProvider struct {
	document accesstoken.JWKS
}

func (s stubJWKSProvider) JWKS() accesstoken.JWKS {
	return s.document
}
