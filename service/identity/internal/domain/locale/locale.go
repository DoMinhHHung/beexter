package locale

import "strings"

const Default = "en"

// ParseBase extracts a lowercase ISO 639-1 base language from a language tag.
// Examples: "en-US" -> "en", "ja_JP" -> "ja".
func ParseBase(raw string) (string, bool) {
	candidate := strings.ToLower(strings.TrimSpace(raw))
	candidate = strings.ReplaceAll(candidate, "_", "-")

	if separator := strings.IndexByte(candidate, '-'); separator >= 0 {
		candidate = candidate[:separator]
	}

	if len(candidate) != 2 {
		return "", false
	}

	for _, character := range candidate {
		if character < 'a' || character > 'z' {
			return "", false
		}
	}

	return candidate, true
}

func Normalize(raw string) string {
	parsed, ok := ParseBase(raw)
	if !ok {
		return Default
	}

	return parsed
}
