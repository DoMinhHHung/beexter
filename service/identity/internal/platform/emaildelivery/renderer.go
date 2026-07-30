package emaildelivery

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"time"
)

//go:embed templates/verify_email.html
var verificationHTMLTemplate string

//go:embed templates/reset_password.html
var passwordResetHTMLTemplate string

var (
	ErrRendererNotInitialized = errors.New(
		"email renderer is not initialized",
	)
	ErrInvalidVerificationURL = errors.New(
		"verification URL is invalid",
	)
)

type RenderedEmail struct {
	Subject  string
	TextBody string
	HTMLBody string
}

type VerificationTemplateData struct {
	Locale          string
	I18n            VerifyEmailI18n
	VerificationURL string
	ExpiresAt       time.Time
	CurrentYear     int
}

type PasswordResetTemplateData struct {
	Locale           string
	I18n             PasswordResetI18n
	PasswordResetURL string
	ExpiresAt        time.Time
	CurrentYear      int
}

type Renderer struct {
	verificationTemplate  *template.Template
	passwordResetTemplate *template.Template
}

func NewRenderer() (*Renderer, error) {
	verificationTemplate, err := template.New(
		"verify_email.html",
	).Parse(verificationHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf(
			"parse embedded verification email template: %w",
			err,
		)
	}

	passwordResetTemplate, err := template.New(
		"reset_password.html",
	).Parse(passwordResetHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf(
			"parse embedded password-reset email template: %w",
			err,
		)
	}

	return &Renderer{
		verificationTemplate:  verificationTemplate,
		passwordResetTemplate: passwordResetTemplate,
	}, nil
}

func (r *Renderer) RenderVerification(
	data VerificationTemplateData,
) (RenderedEmail, error) {
	if r == nil || r.verificationTemplate == nil {
		return RenderedEmail{}, ErrRendererNotInitialized
	}

	parsedURL, err := parseAbsoluteHTTPURL(data.VerificationURL)
	if err != nil {
		return RenderedEmail{}, err
	}
	if data.Locale == "" || data.ExpiresAt.IsZero() || data.CurrentYear < 2000 {
		return RenderedEmail{}, errors.New(
			"verification template data is invalid",
		)
	}
	if err := validateTranslation(data.I18n); err != nil {
		return RenderedEmail{}, fmt.Errorf(
			"validate verification translation: %w",
			err,
		)
	}

	formattedExpiry := data.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC")
	templateData := struct {
		Locale          string
		I18n            VerifyEmailI18n
		VerificationURL template.URL
		ExpiresAt       string
		CurrentYear     int
	}{
		Locale:          data.Locale,
		I18n:            data.I18n,
		VerificationURL: template.URL(parsedURL.String()),
		ExpiresAt:       formattedExpiry,
		CurrentYear:     data.CurrentYear,
	}

	var htmlBuffer bytes.Buffer
	if err := r.verificationTemplate.Execute(&htmlBuffer, templateData); err != nil {
		return RenderedEmail{}, fmt.Errorf(
			"render verification email HTML: %w",
			err,
		)
	}

	textBody := fmt.Sprintf(
		"%s\n\n%s\n\n%s\n%s\n\n%s: %s\n\n%s\n%s\n\n%s\n\n© %d BeexSter. %s\n",
		data.I18n.Title,
		data.I18n.Greeting,
		data.I18n.Message1,
		data.I18n.Message2,
		data.I18n.ExpireMsg,
		formattedExpiry,
		data.I18n.FallbackMsg,
		parsedURL.String(),
		data.I18n.IgnoreMsg,
		data.CurrentYear,
		data.I18n.FooterRight,
	)

	return RenderedEmail{
		Subject:  data.I18n.Subject,
		TextBody: textBody,
		HTMLBody: htmlBuffer.String(),
	}, nil
}

func (r *Renderer) RenderPasswordReset(
	data PasswordResetTemplateData,
) (RenderedEmail, error) {
	if r == nil || r.passwordResetTemplate == nil {
		return RenderedEmail{}, ErrRendererNotInitialized
	}

	parsedURL, err := parseAbsoluteHTTPURL(data.PasswordResetURL)
	if err != nil {
		return RenderedEmail{}, err
	}
	if data.Locale == "" || data.ExpiresAt.IsZero() || data.CurrentYear < 2000 {
		return RenderedEmail{}, errors.New(
			"password-reset template data is invalid",
		)
	}
	if err := validatePasswordResetTranslation(data.I18n); err != nil {
		return RenderedEmail{}, fmt.Errorf(
			"validate password-reset translation: %w",
			err,
		)
	}

	formattedExpiry := data.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC")
	templateData := struct {
		Locale           string
		I18n             PasswordResetI18n
		PasswordResetURL template.URL
		ExpiresAt        string
		CurrentYear      int
	}{
		Locale:           data.Locale,
		I18n:             data.I18n,
		PasswordResetURL: template.URL(parsedURL.String()),
		ExpiresAt:        formattedExpiry,
		CurrentYear:      data.CurrentYear,
	}

	var htmlBuffer bytes.Buffer
	if err := r.passwordResetTemplate.Execute(&htmlBuffer, templateData); err != nil {
		return RenderedEmail{}, fmt.Errorf(
			"render password-reset email HTML: %w",
			err,
		)
	}

	textBody := fmt.Sprintf(
		"%s\n\n%s\n\n%s\n%s\n\n%s: %s\n\n%s\n%s\n\n%s\n\n© %d BeexSter. %s\n",
		data.I18n.Title,
		data.I18n.Greeting,
		data.I18n.Message1,
		data.I18n.Message2,
		data.I18n.ExpireMsg,
		formattedExpiry,
		data.I18n.FallbackMsg,
		parsedURL.String(),
		data.I18n.IgnoreMsg,
		data.CurrentYear,
		data.I18n.FooterRight,
	)

	return RenderedEmail{
		Subject:  data.I18n.Subject,
		TextBody: textBody,
		HTMLBody: htmlBuffer.String(),
	}, nil
}

func parseAbsoluteHTTPURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidVerificationURL, err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, ErrInvalidVerificationURL
	}
	if parsedURL.Host == "" || parsedURL.User != nil {
		return nil, ErrInvalidVerificationURL
	}

	return parsedURL, nil
}
