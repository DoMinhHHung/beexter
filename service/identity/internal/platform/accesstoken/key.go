package accesstoken

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

const minimumRSAKeyBits = 2048

var (
	ErrPrivateKeyUnreadable = errors.New("RSA private key file is unreadable")
	ErrPrivateKeyInvalid    = errors.New("RSA private key is invalid")
	ErrPrivateKeyTooSmall   = errors.New(
		"RSA private key must be at least 2048 bits",
	)
	ErrPublicKeyUnreadable = errors.New("RSA public key file is unreadable")
	ErrPublicKeyInvalid    = errors.New("RSA public key is invalid")
	ErrPublicKeyTooSmall   = errors.New(
		"RSA public key must be at least 2048 bits",
	)
)

// LoadPrivateKey reads and validates a PKCS#8 or PKCS#1 RSA private key from a
// PEM file. Errors intentionally never include PEM or key material.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: private key path is blank", ErrPrivateKeyInvalid)
	}

	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrPrivateKeyUnreadable
	}

	block, rest := pem.Decode(encoded)
	if block == nil {
		return nil, fmt.Errorf("%w: malformed PEM", ErrPrivateKeyInvalid)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf(
			"%w: PEM must contain exactly one private key",
			ErrPrivateKeyInvalid,
		)
	}

	var privateKey *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf(
				"%w: malformed PKCS#8 private key",
				ErrPrivateKeyInvalid,
			)
		}

		var ok bool
		privateKey, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf(
				"%w: PKCS#8 key is not RSA",
				ErrPrivateKeyInvalid,
			)
		}

	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: malformed PKCS#1 private key",
				ErrPrivateKeyInvalid,
			)
		}

	default:
		return nil, fmt.Errorf(
			"%w: unsupported PEM block type",
			ErrPrivateKeyInvalid,
		)
	}

	if err := validatePrivateKey(privateKey); err != nil {
		return nil, err
	}

	return privateKey, nil
}

// LoadPublicKey reads and validates a PKIX or PKCS#1 RSA public key from a
// PEM file. Private-key PEM blocks are intentionally rejected: supplemental
// verification keys must never require private key material. Errors never
// include the configured path, PEM, or key material.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: public key path is blank", ErrPublicKeyInvalid)
	}

	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrPublicKeyUnreadable
	}

	block, rest := pem.Decode(encoded)
	if block == nil {
		return nil, fmt.Errorf("%w: malformed PEM", ErrPublicKeyInvalid)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf(
			"%w: PEM must contain exactly one public key",
			ErrPublicKeyInvalid,
		)
	}

	var publicKey *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		parsed, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf(
				"%w: malformed PKIX public key",
				ErrPublicKeyInvalid,
			)
		}

		var ok bool
		publicKey, ok = parsed.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf(
				"%w: PKIX key is not RSA",
				ErrPublicKeyInvalid,
			)
		}

	case "RSA PUBLIC KEY":
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: malformed PKCS#1 public key",
				ErrPublicKeyInvalid,
			)
		}

	default:
		return nil, fmt.Errorf(
			"%w: unsupported public PEM block type",
			ErrPublicKeyInvalid,
		)
	}

	if err := validatePublicKey(publicKey); err != nil {
		return nil, err
	}

	return publicKey, nil
}

func validatePrivateKey(privateKey *rsa.PrivateKey) error {
	if privateKey == nil || privateKey.N == nil {
		return ErrPrivateKeyInvalid
	}
	if privateKey.N.BitLen() < minimumRSAKeyBits {
		return ErrPrivateKeyTooSmall
	}
	if err := privateKey.Validate(); err != nil {
		return fmt.Errorf("%w: key validation failed", ErrPrivateKeyInvalid)
	}

	return nil
}

func validatePublicKey(publicKey *rsa.PublicKey) error {
	if publicKey == nil || publicKey.N == nil || publicKey.N.Sign() <= 0 ||
		publicKey.N.Bit(0) == 0 || publicKey.E < 3 ||
		publicKey.E > 1<<31-1 || publicKey.E%2 == 0 {
		return ErrPublicKeyInvalid
	}
	if publicKey.N.BitLen() < minimumRSAKeyBits {
		return ErrPublicKeyTooSmall
	}

	return nil
}
