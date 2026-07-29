package idgen

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
	"github.com/google/uuid"
)

var ErrGeneratorNotInitialized = errors.New(
	"UUID v7 generator is not initialized",
)

type UUIDV7 struct {
	random io.Reader
}

func NewUUIDV7() *UUIDV7 {
	return &UUIDV7{
		random: rand.Reader,
	}
}

func (g *UUIDV7) Generate() (identity.ID, error) {
	if g == nil || g.random == nil {
		return "", ErrGeneratorNotInitialized
	}

	value, err := uuid.NewV7FromReader(g.random)
	if err != nil {
		return "", fmt.Errorf("generate UUID v7: %w", err)
	}

	id, err := identity.ParseID(value.String())
	if err != nil {
		return "", fmt.Errorf("validate generated UUID v7: %w", err)
	}

	return id, nil
}
