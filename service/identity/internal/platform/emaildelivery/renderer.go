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

type Renderer struct {
	verificationTemplate *template.Template
}

func NewRenderer() (*Renderer, error) {
	parsedTemplate, err := template.New(
		"verify_email.html",
	).Parse(verificationHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf(
			"parse embedded verification email template: %w",
			err,
		)
	}

	return &Renderer{
		verificationTemplate: parsedTemplate,
	}, nil
}

func (r *Renderer) RenderVerification(
	verificationURL string,
	expiresAt time.Time,
) (RenderedEmail, error) {
	if r == nil || r.verificationTemplate == nil {
		return RenderedEmail{}, ErrRendererNotInitialized
	}

	parsedURL, err := parseAbsoluteHTTPURL(verificationURL)
	if err != nil {
		return RenderedEmail{}, err
	}

	if expiresAt.IsZero() {
		return RenderedEmail{}, errors.New(
			"verification expiration time is required",
		)
	}

	formattedExpiry := expiresAt.UTC().Format(
		"02/01/2006 15:04 UTC",
	)

	templateData := struct {
		VerificationURL template.URL
		ExpiresAt       string
	}{
		VerificationURL: template.URL(parsedURL.String()),
		ExpiresAt:       formattedExpiry,
	}

	var htmlBuffer bytes.Buffer

	if err := r.verificationTemplate.Execute(
		&htmlBuffer,
		templateData,
	); err != nil {
		return RenderedEmail{}, fmt.Errorf(
			"render verification email HTML: %w",
			err,
		)
	}

	textBody := fmt.Sprintf(
		"Xác minh địa chỉ email Beexter\n\n"+
			"Truy cập link sau để xác minh email:\n%s\n\n"+
			"Link hết hạn lúc %s.\n\n"+
			"Nếu mày không tạo tài khoản này, có thể bỏ qua email.\n",
		parsedURL.String(),
		formattedExpiry,
	)

	return RenderedEmail{
		Subject:  "Xác minh địa chỉ email Beexter",
		TextBody: textBody,
		HTMLBody: htmlBuffer.String(),
	}, nil
}

func parseAbsoluteHTTPURL(
	rawURL string,
) (*url.URL, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %v",
			ErrInvalidVerificationURL,
			err,
		)
	}

	if parsedURL.Scheme != "http" &&
		parsedURL.Scheme != "https" {
		return nil, ErrInvalidVerificationURL
	}

	if parsedURL.Host == "" ||
		parsedURL.User != nil {
		return nil, ErrInvalidVerificationURL
	}

	return parsedURL, nil
}
