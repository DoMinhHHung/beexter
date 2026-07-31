package accesstoken

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"
)

func TestJWKSContainsExactlyOneMatchingPublicRSAKey(t *testing.T) {
	t.Parallel()

	privateKey, _ := testRSAKeys(t)
	service := newTestService(t)
	keySet := service.JWKS()
	if len(keySet.Keys) != 1 {
		t.Fatalf("JWKS key count = %d, want 1", len(keySet.Keys))
	}

	key := keySet.Keys[0]
	if key.KeyType != "RSA" || key.Use != "sig" ||
		key.Algorithm != AlgorithmRS256 || key.KeyID != testKeyID {
		t.Fatalf("unexpected JWK metadata: %+v", key)
	}

	modulusBytes, err := base64.RawURLEncoding.DecodeString(key.Modulus)
	if err != nil {
		t.Fatalf("decode modulus: %v", err)
	}
	if new(big.Int).SetBytes(modulusBytes).Cmp(privateKey.PublicKey.N) != 0 {
		t.Fatal("JWK modulus does not match signing key")
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(key.Exponent)
	if err != nil {
		t.Fatalf("decode exponent: %v", err)
	}
	if new(big.Int).SetBytes(exponentBytes).Cmp(
		big.NewInt(int64(privateKey.PublicKey.E)),
	) != 0 {
		t.Fatal("JWK exponent does not match signing key")
	}
	if key.Modulus == "" || key.Exponent == "" ||
		key.Modulus[len(key.Modulus)-1:] == "=" ||
		key.Exponent[len(key.Exponent)-1:] == "=" {
		t.Fatal("JWK integers must use unpadded base64url encoding")
	}
}

func TestJWKSJSONIsDeterministicAndHasNoPrivateParameters(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	first, err := json.Marshal(service.JWKS())
	if err != nil {
		t.Fatalf("marshal first JWKS: %v", err)
	}
	second, err := json.Marshal(service.JWKS())
	if err != nil {
		t.Fatalf("marshal second JWKS: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("JWKS output is not deterministic:\n%s\n%s", first, second)
	}

	var document struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	wantFields := map[string]bool{
		"kty": true,
		"use": true,
		"alg": true,
		"kid": true,
		"n":   true,
		"e":   true,
	}
	if len(document.Keys) != 1 {
		t.Fatalf("JWKS key count = %d", len(document.Keys))
	}
	gotFields := make(map[string]bool, len(document.Keys[0]))
	for field := range document.Keys[0] {
		gotFields[field] = true
	}
	if !reflect.DeepEqual(gotFields, wantFields) {
		t.Fatalf("JWK fields = %#v, want %#v", gotFields, wantFields)
	}
	for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, exists := document.Keys[0][privateField]; exists {
			t.Errorf("JWKS exposed private field %q", privateField)
		}
	}
}

func TestJWKSReturnsCopy(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	first := service.JWKS()
	first.Keys[0].KeyID = "mutated"
	second := service.JWKS()
	if second.Keys[0].KeyID != testKeyID {
		t.Fatalf("caller mutated cached JWKS: %+v", second)
	}
}

func TestNilServiceJWKSIsAnEmptyArray(t *testing.T) {
	t.Parallel()

	var service *RS256
	encoded, err := json.Marshal(service.JWKS())
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	if string(encoded) != `{"keys":[]}` {
		t.Fatalf("nil-service JWKS = %s", encoded)
	}
}
