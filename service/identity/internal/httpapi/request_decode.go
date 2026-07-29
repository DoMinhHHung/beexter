package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

const maxJSONBodySize int64 = 64 * 1024

var (
	errMissingContentType   = errors.New("Content-Type header is required")
	errUnsupportedMediaType = errors.New("Content-Type must be application/json")
	errEmptyRequestBody     = errors.New("request body must not be empty")
	errRequestBodyTooLarge  = errors.New("request body is too large")
	errInvalidJSON          = errors.New("request body contains invalid JSON")
	errMultipleJSONValues   = errors.New("request body must contain one JSON value")
)

func decodeJSONBody(
	w http.ResponseWriter,
	r *http.Request,
	destination any,
) error {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return errMissingContentType
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf(
			"%w: malformed Content-Type",
			errUnsupportedMediaType,
		)
	}

	if mediaType != "application/json" {
		return fmt.Errorf(
			"%w: received %q",
			errUnsupportedMediaType,
			mediaType,
		)
	}

	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		maxJSONBodySize,
	)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return classifyJSONDecodeError(err)
	}

	var trailingValue any

	err = decoder.Decode(&trailingValue)
	switch {
	case errors.Is(err, io.EOF):
		return nil

	case err == nil:
		return errMultipleJSONValues

	default:
		return classifyJSONDecodeError(err)
	}
}

func classifyJSONDecodeError(err error) error {
	if errors.Is(err, io.EOF) {
		return errEmptyRequestBody
	}

	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		return fmt.Errorf(
			"%w: maximum is %d bytes",
			errRequestBodyTooLarge,
			maxBytesError.Limit,
		)
	}

	return fmt.Errorf("%w: %v", errInvalidJSON, err)
}
