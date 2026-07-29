package idgen

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestUUIDV7Generate(t *testing.T) {
	t.Parallel()

	generator := NewUUIDV7()

	id, err := generator.Generate()
	if err != nil {
		t.Fatalf("generate UUID v7: %v", err)
	}

	parsedID, err := uuid.Parse(id.String())
	if err != nil {
		t.Fatalf("parse generated UUID: %v", err)
	}

	if parsedID.Version() != 7 {
		t.Fatalf(
			"expected UUID version 7, got %d",
			parsedID.Version(),
		)
	}

	if parsedID.Variant() != uuid.RFC4122 {
		t.Fatalf(
			"expected RFC 4122 variant, got %v",
			parsedID.Variant(),
		)
	}
}

func TestUUIDV7GenerateFailsWhenRandomSourceFails(t *testing.T) {
	t.Parallel()

	generator := &UUIDV7{
		random: failingReader{},
	}

	_, err := generator.Generate()
	if err == nil {
		t.Fatal("expected generation error")
	}
}

func TestUUIDV7RejectsUninitializedGenerator(t *testing.T) {
	t.Parallel()

	var generator *UUIDV7

	_, err := generator.Generate()

	if !errors.Is(err, ErrGeneratorNotInitialized) {
		t.Fatalf(
			"expected ErrGeneratorNotInitialized, got %v",
			err,
		)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("random source unavailable")
}
