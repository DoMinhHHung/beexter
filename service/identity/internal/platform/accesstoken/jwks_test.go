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

func TestJWKSContainsActiveThenSortedSupplementalKeys(t *testing.T) {
	t.Parallel()

	activePrivateKey, additionalA := testRSAKeys(t)
	additionalZ := testOldRSAKey(t)
	service := newRotatingTestService(t)
	keySet := service.JWKS()
	if len(keySet.Keys) != 3 {
		t.Fatalf("JWKS key count = %d, want 3", len(keySet.Keys))
	}

	wantKeyIDs := []string{testKeyID, "additional-a", "additional-z"}
	wantPublicKeys := map[string]struct {
		modulus  *big.Int
		exponent int
	}{
		testKeyID: {
			modulus:  activePrivateKey.PublicKey.N,
			exponent: activePrivateKey.PublicKey.E,
		},
		"additional-a": {
			modulus:  additionalA.PublicKey.N,
			exponent: additionalA.PublicKey.E,
		},
		"additional-z": {
			modulus:  additionalZ.PublicKey.N,
			exponent: additionalZ.PublicKey.E,
		},
	}

	for index, key := range keySet.Keys {
		if key.KeyID != wantKeyIDs[index] {
			t.Fatalf("key %d kid = %q, want %q", index, key.KeyID, wantKeyIDs[index])
		}
		if key.KeyType != "RSA" || key.Use != "sig" ||
			key.Algorithm != AlgorithmRS256 {
			t.Fatalf("unexpected JWK metadata: %+v", key)
		}

		modulusBytes, err := base64.RawURLEncoding.DecodeString(key.Modulus)
		if err != nil {
			t.Fatalf("decode modulus for %q: %v", key.KeyID, err)
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(key.Exponent)
		if err != nil {
			t.Fatalf("decode exponent for %q: %v", key.KeyID, err)
		}
		want := wantPublicKeys[key.KeyID]
		if new(big.Int).SetBytes(modulusBytes).Cmp(want.modulus) != 0 ||
			new(big.Int).SetBytes(exponentBytes).Cmp(
				big.NewInt(int64(want.exponent)),
			) != 0 {
			t.Fatalf("JWK %q does not match configured public key", key.KeyID)
		}
		if key.Modulus == "" || key.Exponent == "" ||
			key.Modulus[len(key.Modulus)-1:] == "=" ||
			key.Exponent[len(key.Exponent)-1:] == "=" {
			t.Fatalf("JWK %q integers are not unpadded base64url", key.KeyID)
		}
	}
}

func TestJWKSJSONIsDeterministicAndHasNoPrivateParameters(t *testing.T) {
	t.Parallel()

	service := newRotatingTestService(t)
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
	if len(document.Keys) != 3 {
		t.Fatalf("JWKS key count = %d", len(document.Keys))
	}
	for index, key := range document.Keys {
		gotFields := make(map[string]bool, len(key))
		for field := range key {
			gotFields[field] = true
		}
		if !reflect.DeepEqual(gotFields, wantFields) {
			t.Fatalf("JWK %d fields = %#v, want %#v", index, gotFields, wantFields)
		}
		for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, exists := key[privateField]; exists {
				t.Errorf("JWK %d exposed private field %q", index, privateField)
			}
		}
	}
}

func TestJWKSReturnsCopy(t *testing.T) {
	t.Parallel()

	service := newRotatingTestService(t)
	first := service.JWKS()
	first.Keys[0].KeyID = "mutated"
	first.Keys[1].Modulus = "mutated"
	first.Keys = first.Keys[:1]
	second := service.JWKS()
	if len(second.Keys) != 3 || second.Keys[0].KeyID != testKeyID ||
		second.Keys[1].KeyID != "additional-a" ||
		second.Keys[1].Modulus == "mutated" {
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

func newRotatingTestService(t *testing.T) *RS256 {
	t.Helper()

	activePrivateKey, additionalA := testRSAKeys(t)
	additionalZ := testOldRSAKey(t)
	config := validConfig()
	config.VerificationKeys = []VerificationKey{
		{KeyID: "additional-z", PublicKey: &additionalZ.PublicKey},
		{KeyID: "additional-a", PublicKey: &additionalA.PublicKey},
	}
	service, err := New(activePrivateKey, config)
	if err != nil {
		t.Fatalf("create rotating token service: %v", err)
	}
	return service
}
