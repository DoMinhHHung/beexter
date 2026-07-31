package emaildelivery

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	appoutbox "github.com/DoMinhHHung/beexster/service/identity/internal/application/outbox"
)

var ErrPasswordResetMailerNotInitialized = errors.New(
	"password-reset mailer is not initialized",
)

type PasswordResetMailer struct {
	sender          MessageSender
	renderer        *Renderer
	catalog         *PasswordResetCatalog
	resetBaseURL    *url.URL
	messageIDDomain string
	now             func() time.Time
}

func NewPasswordResetMailer(
	sender MessageSender,
	renderer *Renderer,
	catalog *PasswordResetCatalog,
	rawPasswordResetURL string,
) (*PasswordResetMailer, error) {
	if sender == nil || renderer == nil || catalog == nil {
		return nil, ErrPasswordResetMailerNotInitialized
	}

	resetURL, err := parseAbsoluteHTTPURL(rawPasswordResetURL)
	if err != nil {
		return nil, err
	}

	messageIDDomain := strings.TrimSpace(sender.MessageIDDomain())
	if messageIDDomain == "" || strings.ContainsAny(messageIDDomain, "\r\n@") {
		return nil, errors.New("SMTP message ID domain is invalid")
	}

	return &PasswordResetMailer{
		sender:          sender,
		renderer:        renderer,
		catalog:         catalog,
		resetBaseURL:    resetURL,
		messageIDDomain: messageIDDomain,
		now:             time.Now,
	}, nil
}

func (m *PasswordResetMailer) SendPasswordReset(
	ctx context.Context,
	message appoutbox.PasswordResetMessage,
) error {
	if m == nil ||
		m.sender == nil ||
		m.renderer == nil ||
		m.catalog == nil ||
		m.resetBaseURL == nil ||
		m.now == nil {
		return ErrPasswordResetMailerNotInitialized
	}

	if ctx == nil || message.Recipient == "" || message.ExpiresAt.IsZero() {
		return errors.New("password-reset email message is invalid")
	}

	if err := validateVersion7ID(message.EventID); err != nil {
		return fmt.Errorf("validate password-reset event ID: %w", err)
	}
	if err := validateVersion7ID(message.TokenID); err != nil {
		return fmt.Errorf("validate password-reset token ID: %w", err)
	}

	resolvedLocale, translation, err := m.catalog.Lookup(message.Locale)
	if err != nil {
		return fmt.Errorf("resolve password-reset email locale: %w", err)
	}

	resetURL := *m.resetBaseURL
	query := resetURL.Query()
	query.Set("token", message.TokenID)
	resetURL.RawQuery = query.Encode()

	renderedEmail, err := m.renderer.RenderPasswordReset(
		PasswordResetTemplateData{
			Locale:           resolvedLocale,
			I18n:             translation,
			PasswordResetURL: resetURL.String(),
			ExpiresAt:        message.ExpiresAt,
			CurrentYear:      m.now().UTC().Year(),
		},
	)
	if err != nil {
		return fmt.Errorf("render password-reset email: %w", err)
	}

	if err := m.sender.Send(
		ctx,
		Message{
			To:       message.Recipient,
			Subject:  renderedEmail.Subject,
			TextBody: renderedEmail.TextBody,
			HTMLBody: renderedEmail.HTMLBody,
			MessageID: fmt.Sprintf(
				"<%s@%s>",
				message.EventID,
				m.messageIDDomain,
			),
		},
	); err != nil {
		return fmt.Errorf("send password-reset email: %w", err)
	}

	return nil
}

var _ appoutbox.PasswordResetMailer = (*PasswordResetMailer)(nil)
