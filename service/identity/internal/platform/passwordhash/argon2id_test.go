package passwordhash

import (
	"errors"
	"strings"
	"testing"
)

func TestHasherHashAndVerify(t *testing.T) {
	t.Parallel()

	hasher := New()
	password := "Secure1!"

	encodedHash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	expectedPrefix := "$argon2id$v=19$m=65536,t=3,p=4$"

	if !strings.HasPrefix(encodedHash, expectedPrefix) {
		t.Fatalf(
			"expected hash prefix %q, got %q",
			expectedPrefix,
			encodedHash,
		)
	}

	if strings.Contains(encodedHash, password) {
		t.Fatal("encoded hash must not contain raw password")
	}

	matches, err := hasher.Verify(password, encodedHash)
	if err != nil {
		t.Fatalf("verify correct password: %v", err)
	}

	if !matches {
		t.Fatal("expected correct password to match")
	}

	matches, err = hasher.Verify("Wrong1!", encodedHash)
	if err != nil {
		t.Fatalf("verify incorrect password: %v", err)
	}

	if matches {
		t.Fatal("expected incorrect password not to match")
	}
}

func TestHasherUsesRandomSalt(t *testing.T) {
	t.Parallel()

	hasher := New()
	password := "Secure1!"

	firstHash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("create first hash: %v", err)
	}

	secondHash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("create second hash: %v", err)
	}

	if firstHash == secondHash {
		t.Fatal("expected different hashes for the same password")
	}
}

func TestHasherRejectsMalformedHash(t *testing.T) {
	t.Parallel()

	hasher := New()

	tests := []struct {
		name        string
		encodedHash string
	}{
		{
			name:        "empty hash",
			encodedHash: "",
		},
		{
			name: "wrong algorithm",
			encodedHash: "$argon2i$v=19$m=65536,t=3,p=4$" +
				"MTIzNDU2Nzg5MDEyMzQ1Ng$" +
				"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY",
		},
		{
			name: "wrong version",
			encodedHash: "$argon2id$v=18$m=65536,t=3,p=4$" +
				"MTIzNDU2Nzg5MDEyMzQ1Ng$" +
				"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY",
		},
		{
			name: "unexpected memory cost",
			encodedHash: "$argon2id$v=19$m=1048576,t=3,p=4$" +
				"MTIzNDU2Nzg5MDEyMzQ1Ng$" +
				"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY",
		},
		{
			name: "invalid parameters",
			encodedHash: "$argon2id$v=19$m=invalid,t=3,p=4$" +
				"MTIzNDU2Nzg5MDEyMzQ1Ng$" +
				"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY",
		},
		{
			name: "invalid salt encoding",
			encodedHash: "$argon2id$v=19$m=65536,t=3,p=4$***$" +
				"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY",
		},
		{
			name: "invalid hash encoding",
			encodedHash: "$argon2id$v=19$m=65536,t=3,p=4$" +
				"MTIzNDU2Nzg5MDEyMzQ1Ng$***",
		},
		{
			name: "additional segment",
			encodedHash: "$argon2id$v=19$m=65536,t=3,p=4$" +
				"MTIzNDU2Nzg5MDEyMzQ1Ng$" +
				"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY$extra",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			matches, err := hasher.Verify(
				"Secure1!",
				test.encodedHash,
			)

			if matches {
				t.Fatal("malformed hash must not match")
			}

			if !errors.Is(err, ErrInvalidHash) {
				t.Fatalf(
					"expected ErrInvalidHash, got %v",
					err,
				)
			}
		})
	}
}

func TestHasherHandlesRandomSourceFailure(t *testing.T) {
	t.Parallel()

	hasher := &Hasher{
		random: failingReader{},
	}

	_, err := hasher.Hash("Secure1!")
	if err == nil {
		t.Fatal("expected random source error")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("random source unavailable")
}
