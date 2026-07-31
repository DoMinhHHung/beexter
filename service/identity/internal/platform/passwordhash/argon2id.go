package passwordhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	memoryCost      uint32 = 64 * 1024
	iterationCost   uint32 = 3
	parallelismCost uint8  = 4
	saltLength             = 16
	hashLength      uint32 = 32

	minMemoryCost      uint32 = 19 * 1024
	maxMemoryCost      uint32 = 256 * 1024
	minIterationCost   uint32 = 1
	maxIterationCost   uint32 = 10
	minParallelismCost uint8  = 1
	maxParallelismCost uint8  = 8

	minSaltLength = 16
	maxSaltLength = 64
	minHashLength = 16
	maxHashLength = 64
)

var ErrInvalidHash = errors.New("invalid password hash")

type Hasher struct {
	random io.Reader
}

type parameters struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func New() *Hasher {
	return &Hasher{
		random: rand.Reader,
	}
}

func (h *Hasher) Hash(password string) (string, error) {
	if h == nil || h.random == nil {
		return "", errors.New("password hasher is not initialized")
	}

	salt := make([]byte, saltLength)

	if _, err := io.ReadFull(h.random, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	passwordBytes := []byte(password)
	defer clear(passwordBytes)

	derivedKey := argon2.IDKey(
		passwordBytes,
		salt,
		iterationCost,
		memoryCost,
		parallelismCost,
		hashLength,
	)
	defer clear(derivedKey)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedKey := base64.RawStdEncoding.EncodeToString(derivedKey)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memoryCost,
		iterationCost,
		parallelismCost,
		encodedSalt,
		encodedKey,
	), nil
}

func (h *Hasher) Verify(
	password string,
	encodedHash string,
) (bool, error) {
	if h == nil {
		return false, errors.New("password hasher is not initialized")
	}

	params, salt, expectedKey, err := parseHash(encodedHash)
	if err != nil {
		return false, err
	}
	defer clear(expectedKey)

	passwordBytes := []byte(password)
	defer clear(passwordBytes)

	actualKey := argon2.IDKey(
		passwordBytes,
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		uint32(len(expectedKey)),
	)
	defer clear(actualKey)

	return subtle.ConstantTimeCompare(
		expectedKey,
		actualKey,
	) == 1, nil
}

func (h *Hasher) NeedsRehash(encodedHash string) bool {
	params, salt, key, err := parseHash(encodedHash)
	if err != nil {
		return false
	}

	return params.memory != memoryCost ||
		params.iterations != iterationCost ||
		params.parallelism != parallelismCost ||
		len(salt) != saltLength ||
		len(key) != int(hashLength)
}

func parseHash(
	encodedHash string,
) (parameters, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")

	if len(parts) != 6 {
		return parameters{}, nil, nil, ErrInvalidHash
	}

	if parts[0] != "" || parts[1] != "argon2id" {
		return parameters{}, nil, nil, ErrInvalidHash
	}

	version, err := parseVersion(parts[2])
	if err != nil || version != argon2.Version {
		return parameters{}, nil, nil, ErrInvalidHash
	}

	params, err := parseParameters(parts[3])
	if err != nil {
		return parameters{}, nil, nil, ErrInvalidHash
	}

	if params.memory < minMemoryCost || params.memory > maxMemoryCost ||
		params.iterations < minIterationCost || params.iterations > maxIterationCost ||
		params.parallelism < minParallelismCost || params.parallelism > maxParallelismCost {
		return parameters{}, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minSaltLength || len(salt) > maxSaltLength {
		return parameters{}, nil, nil, ErrInvalidHash
	}

	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < minHashLength || len(key) > maxHashLength {
		return parameters{}, nil, nil, ErrInvalidHash
	}

	return params, salt, key, nil
}

func parseVersion(rawVersion string) (int, error) {
	name, value, found := strings.Cut(rawVersion, "=")
	if !found || name != "v" || value == "" {
		return 0, ErrInvalidHash
	}

	version, err := strconv.Atoi(value)
	if err != nil {
		return 0, ErrInvalidHash
	}

	return version, nil
}

func parseParameters(rawParameters string) (parameters, error) {
	parts := strings.Split(rawParameters, ",")
	if len(parts) != 3 {
		return parameters{}, ErrInvalidHash
	}

	memory, err := parseNamedUint(parts[0], "m", 32)
	if err != nil {
		return parameters{}, ErrInvalidHash
	}

	iterations, err := parseNamedUint(parts[1], "t", 32)
	if err != nil {
		return parameters{}, ErrInvalidHash
	}

	parallelism, err := parseNamedUint(parts[2], "p", 8)
	if err != nil {
		return parameters{}, ErrInvalidHash
	}

	if memory == 0 || iterations == 0 || parallelism == 0 {
		return parameters{}, ErrInvalidHash
	}

	return parameters{
		memory:      uint32(memory),
		iterations:  uint32(iterations),
		parallelism: uint8(parallelism),
	}, nil
}

func parseNamedUint(
	rawValue string,
	expectedName string,
	bitSize int,
) (uint64, error) {
	name, value, found := strings.Cut(rawValue, "=")

	if !found || name != expectedName || value == "" {
		return 0, ErrInvalidHash
	}

	parsed, err := strconv.ParseUint(value, 10, bitSize)
	if err != nil {
		return 0, ErrInvalidHash
	}

	return parsed, nil
}
