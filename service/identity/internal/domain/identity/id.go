package identity

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var ErrInvalidID = errors.New("invalid identity ID")

type ID string

func ParseID(rawID string) (ID, error) {
	if rawID == "" {
		return "", ErrInvalidID
	}

	parsedID, err := uuid.Parse(rawID)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidID, err)
	}

	if parsedID.Version() != 7 {
		return "", ErrInvalidID
	}

	if parsedID.Variant() != uuid.RFC4122 {
		return "", ErrInvalidID
	}

	if parsedID.String() != rawID {
		return "", ErrInvalidID
	}

	return ID(rawID), nil
}

func (id ID) String() string {
	return string(id)
}

func (id ID) IsZero() bool {
	return id == ""
}
