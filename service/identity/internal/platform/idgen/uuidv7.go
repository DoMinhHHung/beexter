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
	value, err := g.GenerateString()
	if err != nil {
		return "", err
	}

	id, err := identity.ParseID(value)
	if err != nil {
		return "", fmt.Errorf(
			"validate generated identity UUID v7: %w",
			err,
		)
	}

	return id, nil
}

func (g *UUIDV7) GenerateString() (string, error) {
	if g == nil || g.random == nil {
		return "", ErrGeneratorNotInitialized
	}

	value, err := uuid.NewV7FromReader(g.random)
	if err != nil {
		return "", fmt.Errorf("generate UUID v7: %w", err)
	}

	return value.String(), nil
}
