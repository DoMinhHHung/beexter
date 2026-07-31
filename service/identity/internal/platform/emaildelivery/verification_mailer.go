package emaildelivery

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	appoutbox "github.com/DoMinhHHung/beexster/service/identity/internal/application/outbox"
	"github.com/google/uuid"
)

var ErrVerificationMailerNotInitialized = errors.New(
	"verification mailer is not initialized",
)

type MessageSender interface {
	Send(ctx context.Context, message Message) error
	MessageIDDomain() string
}

type VerificationMailer struct {
	sender              MessageSender
	renderer            *Renderer
	catalog             *Catalog
	verificationBaseURL *url.URL
	messageIDDomain     string
	now                 func() time.Time
}

func NewVerificationMailer(
	sender MessageSender,
	renderer *Renderer,
	catalog *Catalog,
	rawVerificationURL string,
) (*VerificationMailer, error) {
	if sender == nil || renderer == nil || catalog == nil {
		return nil, ErrVerificationMailerNotInitialized
	}

	verificationURL, err := parseAbsoluteHTTPURL(rawVerificationURL)
	if err != nil {
		return nil, err
	}

	messageIDDomain := strings.TrimSpace(sender.MessageIDDomain())
	if messageIDDomain == "" ||
		strings.ContainsAny(messageIDDomain, "\r\n@") {
		return nil, errors.New("SMTP message ID domain is invalid")
	}

	return &VerificationMailer{
		sender:              sender,
		renderer:            renderer,
		catalog:             catalog,
		verificationBaseURL: verificationURL,
		messageIDDomain:     messageIDDomain,
		now:                 time.Now,
	}, nil
}

func (m *VerificationMailer) SendVerification(
	ctx context.Context,
	message appoutbox.VerificationMessage,
) error {
	if m == nil ||
		m.sender == nil ||
		m.renderer == nil ||
		m.catalog == nil ||
		m.verificationBaseURL == nil ||
		m.now == nil {
		return ErrVerificationMailerNotInitialized
	}

	if ctx == nil ||
		message.Recipient == "" ||
		message.ExpiresAt.IsZero() {
		return errors.New("verification email message is invalid")
	}

	if err := validateVersion7ID(message.EventID); err != nil {
		return fmt.Errorf("validate email event ID: %w", err)
	}

	if err := validateVersion7ID(message.TokenID); err != nil {
		return fmt.Errorf("validate verification token ID: %w", err)
	}

	resolvedLocale, translation, err := m.catalog.Lookup(message.Locale)
	if err != nil {
		return fmt.Errorf("resolve verification email locale: %w", err)
	}

	verificationURL := *m.verificationBaseURL
	query := verificationURL.Query()
	query.Set("token", message.TokenID)
	verificationURL.RawQuery = query.Encode()

	renderedEmail, err := m.renderer.RenderVerification(
		VerificationTemplateData{
			Locale:          resolvedLocale,
			I18n:            translation,
			VerificationURL: verificationURL.String(),
			ExpiresAt:       message.ExpiresAt,
			CurrentYear:     m.now().UTC().Year(),
		},
	)
	if err != nil {
		return fmt.Errorf("render verification email: %w", err)
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
		return fmt.Errorf("send verification email: %w", err)
	}

	return nil
}

func validateVersion7ID(rawID string) error {
	parsedID, err := uuid.Parse(rawID)
	if err != nil {
		return fmt.Errorf("parse UUID: %w", err)
	}

	if parsedID.Version() != 7 ||
		parsedID.Variant() != uuid.RFC4122 ||
		parsedID.String() != rawID {
		return errors.New("ID must be a canonical UUID v7")
	}

	return nil
}

var _ appoutbox.VerificationMailer = (*VerificationMailer)(nil)
