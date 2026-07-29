package identity

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestParseID(t *testing.T) {
	t.Parallel()

	validUUID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("generate UUID v7: %v", err)
	}

	tests := []struct {
		name        string
		rawID       string
		expectError bool
	}{
		{
			name:  "valid UUID v7",
			rawID: validUUID.String(),
		},
		{
			name:        "empty ID",
			rawID:       "",
			expectError: true,
		},
		{
			name:        "invalid UUID",
			rawID:       "not-a-uuid",
			expectError: true,
		},
		{
			name:        "UUID v4 is rejected",
			rawID:       uuid.NewString(),
			expectError: true,
		},
		{
			name:        "uppercase representation is rejected",
			rawID:       "0198F124-659F-7CBD-A441-DC7EEA175073",
			expectError: true,
		},
		{
			name:        "compact representation is rejected",
			rawID:       "0198f124659f7cbda441dc7eea175073",
			expectError: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			id, err := ParseID(test.rawID)

			if test.expectError {
				if !errors.Is(err, ErrInvalidID) {
					t.Fatalf(
						"expected ErrInvalidID, got %v",
						err,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if id.String() != test.rawID {
				t.Fatalf(
					"expected ID %q, got %q",
					test.rawID,
					id,
				)
			}
		})
	}
}
