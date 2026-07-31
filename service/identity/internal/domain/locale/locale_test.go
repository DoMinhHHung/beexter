package locale

import "testing"

func TestParseBase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
		valid    bool
	}{
		{name: "base", input: "vi", expected: "vi", valid: true},
		{name: "region", input: "en-US", expected: "en", valid: true},
		{name: "underscore", input: "ja_JP", expected: "ja", valid: true},
		{name: "uppercase", input: "VI-vn", expected: "vi", valid: true},
		{name: "empty", input: "", valid: false},
		{name: "wildcard", input: "*", valid: false},
		{name: "three-letter", input: "eng", valid: false},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual, valid := ParseBase(test.input)
			if valid != test.valid {
				t.Fatalf("expected valid=%t, got %t", test.valid, valid)
			}

			if actual != test.expected {
				t.Fatalf("expected %q, got %q", test.expected, actual)
			}
		})
	}
}

func TestNormalizeFallsBackToEnglish(t *testing.T) {
	t.Parallel()

	if actual := Normalize("invalid"); actual != Default {
		t.Fatalf("expected default locale %q, got %q", Default, actual)
	}
}
