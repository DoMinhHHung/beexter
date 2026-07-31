package emaildelivery

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	domainlocale "github.com/DoMinhHHung/beexster/service/identity/internal/domain/locale"
)

//go:embed locales/password_reset/*.json
var embeddedPasswordResetLocales embed.FS

type PasswordResetI18n struct {
	Subject     string `json:"Subject"`
	Title       string `json:"Title"`
	Greeting    string `json:"Greeting"`
	Message1    string `json:"Message1"`
	Message2    string `json:"Message2"`
	ButtonText  string `json:"ButtonText"`
	ExpireMsg   string `json:"ExpireMsg"`
	FallbackMsg string `json:"FallbackMsg"`
	IgnoreMsg   string `json:"IgnoreMsg"`
	FooterRight string `json:"FooterRight"`
}

type PasswordResetCatalog struct {
	translations  map[string]PasswordResetI18n
	defaultLocale string
}

func NewPasswordResetCatalog() (*PasswordResetCatalog, error) {
	const directory = "locales/password_reset"

	entries, err := fs.ReadDir(embeddedPasswordResetLocales, directory)
	if err != nil {
		return nil, fmt.Errorf("read embedded password-reset locales: %w", err)
	}

	translations := make(map[string]PasswordResetI18n, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		rawLocale := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		locale, valid := domainlocale.ParseBase(rawLocale)
		if !valid || locale != rawLocale {
			return nil, fmt.Errorf(
				"%w: password-reset locale filename %q must be a lowercase two-letter language code",
				ErrInvalidTranslation,
				entry.Name(),
			)
		}
		if _, exists := translations[locale]; exists {
			return nil, fmt.Errorf(
				"%w: duplicate password-reset locale %q",
				ErrInvalidTranslation,
				locale,
			)
		}

		translation, err := readPasswordResetTranslation(
			directory + "/" + entry.Name(),
		)
		if err != nil {
			return nil, err
		}
		translations[locale] = translation
	}

	if _, exists := translations[domainlocale.Default]; !exists {
		return nil, fmt.Errorf(
			"%w: default password-reset locale %q is missing",
			ErrInvalidTranslation,
			domainlocale.Default,
		)
	}

	return &PasswordResetCatalog{
		translations:  translations,
		defaultLocale: domainlocale.Default,
	}, nil
}

func (c *PasswordResetCatalog) Lookup(
	requestedLocale string,
) (string, PasswordResetI18n, error) {
	if c == nil || len(c.translations) == 0 || c.defaultLocale == "" {
		return "", PasswordResetI18n{}, ErrCatalogNotInitialized
	}

	locale := domainlocale.Normalize(requestedLocale)
	translation, exists := c.translations[locale]
	if exists {
		return locale, translation, nil
	}

	translation, exists = c.translations[c.defaultLocale]
	if !exists {
		return "", PasswordResetI18n{}, ErrCatalogNotInitialized
	}
	return c.defaultLocale, translation, nil
}

func readPasswordResetTranslation(
	path string,
) (PasswordResetI18n, error) {
	rawTranslation, err := embeddedPasswordResetLocales.ReadFile(path)
	if err != nil {
		return PasswordResetI18n{}, fmt.Errorf(
			"read embedded password-reset translation %s: %w",
			path,
			err,
		)
	}

	decoder := json.NewDecoder(bytes.NewReader(rawTranslation))
	decoder.DisallowUnknownFields()

	var translation PasswordResetI18n
	if err := decoder.Decode(&translation); err != nil {
		return PasswordResetI18n{}, fmt.Errorf(
			"decode embedded password-reset translation %s: %w",
			path,
			err,
		)
	}

	var trailingValue any
	if err := decoder.Decode(&trailingValue); !errors.Is(err, io.EOF) {
		if err == nil {
			return PasswordResetI18n{}, fmt.Errorf(
				"%w: password-reset translation %s contains multiple JSON values",
				ErrInvalidTranslation,
				path,
			)
		}
		return PasswordResetI18n{}, fmt.Errorf(
			"decode trailing password-reset translation %s: %w",
			path,
			err,
		)
	}

	if err := validatePasswordResetTranslation(translation); err != nil {
		return PasswordResetI18n{}, fmt.Errorf(
			"%w: password-reset translation %s: %v",
			ErrInvalidTranslation,
			path,
			err,
		)
	}

	return translation, nil
}

func validatePasswordResetTranslation(
	translation PasswordResetI18n,
) error {
	fields := map[string]string{
		"Subject":     translation.Subject,
		"Title":       translation.Title,
		"Greeting":    translation.Greeting,
		"Message1":    translation.Message1,
		"Message2":    translation.Message2,
		"ButtonText":  translation.ButtonText,
		"ExpireMsg":   translation.ExpireMsg,
		"FallbackMsg": translation.FallbackMsg,
		"IgnoreMsg":   translation.IgnoreMsg,
		"FooterRight": translation.FooterRight,
	}

	for fieldName, value := range fields {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("field %s is required", fieldName)
		}
		if fieldName == "Subject" && strings.ContainsAny(value, "\r\n") {
			return errors.New("Subject must not contain CR or LF")
		}
	}

	return nil
}
