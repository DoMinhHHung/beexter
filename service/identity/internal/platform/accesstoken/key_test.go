package accesstoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadPrivateKeySupportsPKCS1AndPKCS8(t *testing.T) {
	t.Parallel()

	privateKey, _ := testRSAKeys(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}

	tests := []struct {
		name      string
		blockType string
		der       []byte
	}{
		{
			name:      "PKCS#1",
			blockType: "RSA PRIVATE KEY",
			der:       x509.MarshalPKCS1PrivateKey(privateKey),
		},
		{name: "PKCS#8", blockType: "PRIVATE KEY", der: pkcs8},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := writePEM(t, test.blockType, test.der)
			loaded, loadErr := LoadPrivateKey(path)
			if loadErr != nil {
				t.Fatalf("load key: %v", loadErr)
			}
			if loaded.N.Cmp(privateKey.N) != 0 || loaded.D.Cmp(privateKey.D) != 0 {
				t.Fatal("loaded key does not match source key")
			}
		})
	}
}

func TestLoadPrivateKeyRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	t.Run("blank path", func(t *testing.T) {
		t.Parallel()
		_, err := LoadPrivateKey(" \t ")
		if !errors.Is(err, ErrPrivateKeyInvalid) {
			t.Fatalf("error = %v, want ErrPrivateKeyInvalid", err)
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "missing.pem")
		_, err := LoadPrivateKey(path)
		if !errors.Is(err, ErrPrivateKeyUnreadable) {
			t.Fatalf("error = %v, want ErrPrivateKeyUnreadable", err)
		}
		if strings.Contains(err.Error(), path) {
			t.Fatalf("error exposed configured path: %v", err)
		}
	})

	t.Run("unreadable path cannot echo pasted key material", func(t *testing.T) {
		t.Parallel()
		sensitivePath := "-----BEGIN " + "PRIVATE KEY-----pasted-secret-material"
		_, err := LoadPrivateKey(sensitivePath)
		if !errors.Is(err, ErrPrivateKeyUnreadable) {
			t.Fatalf("error = %v, want ErrPrivateKeyUnreadable", err)
		}
		if strings.Contains(err.Error(), sensitivePath) ||
			strings.Contains(err.Error(), "pasted-secret-material") {
			t.Fatalf("error exposed configured key material: %v", err)
		}
	})

	t.Run("malformed PEM", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "malformed.pem")
		if err := os.WriteFile(path, []byte("not PEM private material"), 0o600); err != nil {
			t.Fatalf("write malformed PEM: %v", err)
		}
		_, err := LoadPrivateKey(path)
		if !errors.Is(err, ErrPrivateKeyInvalid) {
			t.Fatalf("error = %v, want ErrPrivateKeyInvalid", err)
		}
	})

	t.Run("malformed PKCS#8", func(t *testing.T) {
		t.Parallel()
		path := writePEM(t, "PRIVATE KEY", []byte("not DER"))
		_, err := LoadPrivateKey(path)
		if !errors.Is(err, ErrPrivateKeyInvalid) {
			t.Fatalf("error = %v, want ErrPrivateKeyInvalid", err)
		}
	})

	t.Run("non-RSA PKCS#8", func(t *testing.T) {
		t.Parallel()
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate EC key: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(ecKey)
		if err != nil {
			t.Fatalf("marshal EC key: %v", err)
		}
		_, err = LoadPrivateKey(writePEM(t, "PRIVATE KEY", der))
		if !errors.Is(err, ErrPrivateKeyInvalid) {
			t.Fatalf("error = %v, want ErrPrivateKeyInvalid", err)
		}
	})

	t.Run("unsupported PEM block", func(t *testing.T) {
		t.Parallel()
		_, err := LoadPrivateKey(writePEM(t, "PUBLIC KEY", []byte("DER")))
		if !errors.Is(err, ErrPrivateKeyInvalid) {
			t.Fatalf("error = %v, want ErrPrivateKeyInvalid", err)
		}
	})

	t.Run("multiple PEM blocks", func(t *testing.T) {
		t.Parallel()
		privateKey, _ := testRSAKeys(t)
		block := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})
		path := filepath.Join(t.TempDir(), "multiple.pem")
		if err := os.WriteFile(path, append(block, block...), 0o600); err != nil {
			t.Fatalf("write multiple PEM blocks: %v", err)
		}
		_, err := LoadPrivateKey(path)
		if !errors.Is(err, ErrPrivateKeyInvalid) {
			t.Fatalf("error = %v, want ErrPrivateKeyInvalid", err)
		}
	})
}

func TestLoadPrivateKeyRejectsRSAKeySmallerThan2048Bits(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak RSA key: %v", err)
	}
	path := writePEM(
		t,
		"RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(privateKey),
	)
	_, err = LoadPrivateKey(path)
	if !errors.Is(err, ErrPrivateKeyTooSmall) {
		t.Fatalf("error = %v, want ErrPrivateKeyTooSmall", err)
	}
}

func TestNewValidatesConfigurationAndPrivateKey(t *testing.T) {
	t.Parallel()

	privateKey, _ := testRSAKeys(t)
	tests := []struct {
		name   string
		key    *rsa.PrivateKey
		mutate func(*Config)
		want   error
	}{
		{name: "nil key", key: nil, want: ErrPrivateKeyInvalid},
		{
			name: "blank issuer",
			key:  privateKey,
			mutate: func(c *Config) {
				c.Issuer = " \t"
			},
			want: ErrConfigInvalid,
		},
		{
			name: "blank audience",
			key:  privateKey,
			mutate: func(c *Config) {
				c.Audience = ""
			},
			want: ErrConfigInvalid,
		},
		{
			name: "blank key ID",
			key:  privateKey,
			mutate: func(c *Config) {
				c.KeyID = " "
			},
			want: ErrConfigInvalid,
		},
		{
			name: "zero TTL",
			key:  privateKey,
			mutate: func(c *Config) {
				c.AccessTokenTTL = 0
			},
			want: ErrConfigInvalid,
		},
		{
			name: "TTL over one hour",
			key:  privateKey,
			mutate: func(c *Config) {
				c.AccessTokenTTL = time.Hour + time.Nanosecond
			},
			want: ErrConfigInvalid,
		},
		{
			name: "negative clock skew",
			key:  privateKey,
			mutate: func(c *Config) {
				c.AllowedClockSkew = -time.Nanosecond
			},
			want: ErrConfigInvalid,
		},
		{
			name: "clock skew over two minutes",
			key:  privateKey,
			mutate: func(c *Config) {
				c.AllowedClockSkew = 2*time.Minute + time.Nanosecond
			},
			want: ErrConfigInvalid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := validConfig()
			if test.mutate != nil {
				test.mutate(&config)
			}
			_, err := New(test.key, config)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewTrimsTextConfiguration(t *testing.T) {
	t.Parallel()

	privateKey, _ := testRSAKeys(t)
	config := validConfig()
	config.Issuer = "  " + config.Issuer + "  "
	config.Audience = "\t" + config.Audience + "\n"
	config.KeyID = " " + config.KeyID + " "
	service, err := New(privateKey, config)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	if service.issuer != testIssuer || service.audience != testAudience ||
		service.keyID != testKeyID {
		t.Fatalf("configuration was not normalized: %+v", service)
	}
}

func TestErrorsDoNotContainPrivateKeyPEM(t *testing.T) {
	t.Parallel()

	privateKey, _ := testRSAKeys(t)
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	path := filepath.Join(t.TempDir(), "trailing.pem")
	contents := append(privatePEM, []byte("secret-trailing-marker")...)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	_, err := LoadPrivateKey(path)
	if err == nil {
		t.Fatal("expected malformed key error")
	}
	if strings.Contains(err.Error(), string(privatePEM)) ||
		strings.Contains(err.Error(), "secret-trailing-marker") {
		t.Fatalf("error exposed private input: %v", err)
	}
}

func writePEM(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write PEM: %v", err)
	}
	return path
}
