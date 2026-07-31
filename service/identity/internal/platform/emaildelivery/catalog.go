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

const defaultCatalogLocale = domainlocale.Default

//go:embed locales/verify_email/*.json
var embeddedVerifyEmailLocales embed.FS

var (
	ErrCatalogNotInitialized = errors.New(
		"email translation catalog is not initialized",
	)
	ErrInvalidTranslation = errors.New(
		"email translation is invalid",
	)
)

type VerifyEmailI18n struct {
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

type Catalog struct {
	translations  map[string]VerifyEmailI18n
	defaultLocale string
}

func NewCatalog() (*Catalog, error) {
	const directory = "locales/verify_email"

	entries, err := fs.ReadDir(embeddedVerifyEmailLocales, directory)
	if err != nil {
		return nil, fmt.Errorf(
			"read embedded verification-email locales: %w",
			err,
		)
	}

	translations := make(map[string]VerifyEmailI18n, len(entries))

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		rawLocale := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		locale, valid := domainlocale.ParseBase(rawLocale)
		if !valid || locale != rawLocale {
			return nil, fmt.Errorf(
				"%w: locale filename %q must be a lowercase two-letter language code",
				ErrInvalidTranslation,
				entry.Name(),
			)
		}

		if _, exists := translations[locale]; exists {
			return nil, fmt.Errorf(
				"%w: duplicate locale %q",
				ErrInvalidTranslation,
				locale,
			)
		}

		translation, err := readTranslation(
			directory + "/" + entry.Name(),
		)
		if err != nil {
			return nil, err
		}

		translations[locale] = translation
	}

	if _, exists := translations[defaultCatalogLocale]; !exists {
		return nil, fmt.Errorf(
			"%w: default locale %q is missing",
			ErrInvalidTranslation,
			defaultCatalogLocale,
		)
	}

	return &Catalog{
		translations:  translations,
		defaultLocale: defaultCatalogLocale,
	}, nil
}

func (c *Catalog) Lookup(
	requestedLocale string,
) (string, VerifyEmailI18n, error) {
	if c == nil ||
		len(c.translations) == 0 ||
		c.defaultLocale == "" {
		return "", VerifyEmailI18n{}, ErrCatalogNotInitialized
	}

	locale := domainlocale.Normalize(requestedLocale)
	translation, exists := c.translations[locale]
	if exists {
		return locale, translation, nil
	}

	translation, exists = c.translations[c.defaultLocale]
	if !exists {
		return "", VerifyEmailI18n{}, ErrCatalogNotInitialized
	}

	return c.defaultLocale, translation, nil
}

func readTranslation(path string) (VerifyEmailI18n, error) {
	rawTranslation, err := embeddedVerifyEmailLocales.ReadFile(path)
	if err != nil {
		return VerifyEmailI18n{}, fmt.Errorf(
			"read embedded translation %s: %w",
			path,
			err,
		)
	}

	decoder := json.NewDecoder(bytes.NewReader(rawTranslation))
	decoder.DisallowUnknownFields()

	var translation VerifyEmailI18n
	if err := decoder.Decode(&translation); err != nil {
		return VerifyEmailI18n{}, fmt.Errorf(
			"decode embedded translation %s: %w",
			path,
			err,
		)
	}

	var trailingValue any
	if err := decoder.Decode(&trailingValue); !errors.Is(err, io.EOF) {
		if err == nil {
			return VerifyEmailI18n{}, fmt.Errorf(
				"%w: translation %s contains multiple JSON values",
				ErrInvalidTranslation,
				path,
			)
		}

		return VerifyEmailI18n{}, fmt.Errorf(
			"decode trailing translation %s: %w",
			path,
			err,
		)
	}

	if err := validateTranslation(translation); err != nil {
		return VerifyEmailI18n{}, fmt.Errorf(
			"%w: translation %s: %v",
			ErrInvalidTranslation,
			path,
			err,
		)
	}

	return translation, nil
}

func validateTranslation(translation VerifyEmailI18n) error {
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

		if strings.ContainsAny(value, "\r\n") && fieldName == "Subject" {
			return errors.New("Subject must not contain CR or LF")
		}
	}

	return nil
}
