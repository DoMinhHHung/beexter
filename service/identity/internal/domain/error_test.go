package domain

import (
	"errors"
	"testing"
)

func TestErrorUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("database unavailable")
	err := WrapError(ErrInternal, cause)

	if !errors.Is(err, cause) {
		t.Fatal("expected wrapped cause to be discoverable")
	}
}

func TestErrorWithoutCause(t *testing.T) {
	t.Parallel()

	err := NewError(ErrInvalidInput)

	if err.Error() != string(ErrInvalidInput) {
		t.Fatalf(
			"expected %q, got %q",
			ErrInvalidInput,
			err.Error(),
		)
	}
}
