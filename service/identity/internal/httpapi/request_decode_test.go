package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testJSONRequest struct {
	Email string `json:"email"`
}

func TestDecodeJSONBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		contentType   string
		body          string
		expectedEmail string
		expectedError error
	}{
		{
			name:          "valid JSON",
			contentType:   "application/json",
			body:          `{"email":"user@example.com"}`,
			expectedEmail: "user@example.com",
		},
		{
			name:          "valid JSON with charset",
			contentType:   "application/json; charset=utf-8",
			body:          `{"email":"user@example.com"}`,
			expectedEmail: "user@example.com",
		},
		{
			name:          "missing Content-Type",
			body:          `{"email":"user@example.com"}`,
			expectedError: errMissingContentType,
		},
		{
			name:          "unsupported Content-Type",
			contentType:   "text/plain",
			body:          `{"email":"user@example.com"}`,
			expectedError: errUnsupportedMediaType,
		},
		{
			name:          "empty body",
			contentType:   "application/json",
			body:          "",
			expectedError: errEmptyRequestBody,
		},
		{
			name:          "malformed JSON",
			contentType:   "application/json",
			body:          `{"email":`,
			expectedError: errInvalidJSON,
		},
		{
			name:          "unknown field",
			contentType:   "application/json",
			body:          `{"email":"user@example.com","role":"ADMIN"}`,
			expectedError: errInvalidJSON,
		},
		{
			name:          "multiple JSON values",
			contentType:   "application/json",
			body:          `{"email":"first@example.com"} {"email":"second@example.com"}`,
			expectedError: errMultipleJSONValues,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(
				http.MethodPost,
				"/test",
				strings.NewReader(test.body),
			)

			if test.contentType != "" {
				request.Header.Set(
					"Content-Type",
					test.contentType,
				)
			}

			response := httptest.NewRecorder()
			var payload testJSONRequest

			err := decodeJSONBody(
				response,
				request,
				&payload,
			)

			if test.expectedError != nil {
				if !errors.Is(err, test.expectedError) {
					t.Fatalf(
						"expected error %v, got %v",
						test.expectedError,
						err,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if payload.Email != test.expectedEmail {
				t.Fatalf(
					"expected email %q, got %q",
					test.expectedEmail,
					payload.Email,
				)
			}
		})
	}
}

func TestDecodeJSONBodyRejectsLargeBody(t *testing.T) {
	t.Parallel()

	largeValue := strings.Repeat(
		"a",
		int(maxJSONBodySize),
	)

	body := `{"email":"` + largeValue + `"}`

	request := httptest.NewRequest(
		http.MethodPost,
		"/test",
		strings.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()
	var payload testJSONRequest

	err := decodeJSONBody(
		response,
		request,
		&payload,
	)

	if !errors.Is(err, errRequestBodyTooLarge) {
		t.Fatalf(
			"expected body-too-large error, got %v",
			err,
		)
	}
}
