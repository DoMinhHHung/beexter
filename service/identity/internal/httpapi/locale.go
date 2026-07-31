package httpapi

import (
	"strconv"
	"strings"

	domainlocale "github.com/DoMinhHHung/beexster/service/identity/internal/domain/locale"
)

func parseAcceptLanguage(headerValue string) string {
	bestLocale := domainlocale.Default
	bestQuality := -1.0

	for _, rawPreference := range strings.Split(headerValue, ",") {
		preference := strings.TrimSpace(rawPreference)
		if preference == "" {
			continue
		}

		parts := strings.Split(preference, ";")
		locale, valid := domainlocale.ParseBase(parts[0])
		if !valid {
			continue
		}

		quality := 1.0
		validQuality := true

		for _, rawParameter := range parts[1:] {
			name, value, found := strings.Cut(
				strings.TrimSpace(rawParameter),
				"=",
			)
			if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}

			parsedQuality, err := strconv.ParseFloat(
				strings.TrimSpace(value),
				64,
			)
			if err != nil || parsedQuality < 0 || parsedQuality > 1 {
				validQuality = false
				break
			}

			quality = parsedQuality
		}

		if !validQuality || quality <= 0 {
			continue
		}

		if quality > bestQuality {
			bestLocale = locale
			bestQuality = quality
		}
	}

	return bestLocale
}
