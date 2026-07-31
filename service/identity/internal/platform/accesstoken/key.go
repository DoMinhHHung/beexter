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
