package httpapi

import "testing"

func TestParseAcceptLanguage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{name: "empty", header: "", expected: "en"},
		{name: "region", header: "ja-JP", expected: "ja"},
		{
			name:     "quality order",
			header:   "vi;q=0.7, ja-JP;q=0.9, en;q=0.8",
			expected: "ja",
		},
		{
			name:     "zero quality ignored",
			header:   "vi;q=0, en;q=0.5",
			expected: "en",
		},
		{
			name:     "unsupported remains requested base",
			header:   "fr-CA, en;q=0.5",
			expected: "fr",
		},
		{
			name:     "invalid falls back",
			header:   "*, invalid;q=0.9",
			expected: "en",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual := parseAcceptLanguage(test.header)
			if actual != test.expected {
				t.Fatalf("expected %q, got %q", test.expected, actual)
			}
		})
	}
}
