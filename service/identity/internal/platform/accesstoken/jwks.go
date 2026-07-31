package accesstoken

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

const (
	AlgorithmRS256 = "RS256"
	JWTType        = "JWT"
)

// JWK is the public RSA signing key representation returned by the Identity
// Service's JWKS endpoint. It intentionally has no private-key fields.
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func newJWK(publicKey *rsa.PublicKey, keyID string) JWK {
	return JWK{
		KeyType:   "RSA",
		Use:       "sig",
		Algorithm: AlgorithmRS256,
		KeyID:     keyID,
		Modulus: base64.RawURLEncoding.EncodeToString(
			publicKey.N.Bytes(),
		),
		Exponent: base64.RawURLEncoding.EncodeToString(
			big.NewInt(int64(publicKey.E)).Bytes(),
		),
	}
}

// JWKS returns the active public key first, followed by supplemental
// verification keys sorted by key ID. The returned slice is a copy, so callers
// cannot mutate the service's cached representation.
func (s *RS256) JWKS() JWKS {
	if s == nil || len(s.publicJWKS) == 0 {
		return JWKS{Keys: []JWK{}}
	}

	keys := make([]JWK, len(s.publicJWKS))
	copy(keys, s.publicJWKS)
	return JWKS{Keys: keys}
}
