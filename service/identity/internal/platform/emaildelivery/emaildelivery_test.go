package emaildelivery

import (
	"context"
	"io"
	"log/slog"
	"net/mail"
	"strings"
	"testing"
	"time"

	appoutbox "github.com/DoMinhHHung/beexter/service/identity/internal/application/outbox"
)

const (
	emailTestEventID = "0198f124-659f-7cbd-a441-dc7eea175073"

	emailTestTokenID = "0198f124-659f-7cbd-a441-dc7eea175074"
)

func TestRendererUsesEmbeddedHTMLTemplate(t *testing.T) {
	t.Parallel()

	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("create renderer: %v", err)
	}

	rendered, err := renderer.RenderVerification(
		"https://example.com/verify?token=test&source=email",
		time.Date(
			2026,
			time.July,
			30,
			4,
			0,
			0,
			0,
			time.UTC,
		),
	)
	if err != nil {
		t.Fatalf("render verification email: %v", err)
	}

	if !strings.Contains(
		rendered.HTMLBody,
		"<!doctype html>",
	) {
		t.Fatal("expected embedded HTML document")
	}

	if !strings.Contains(
		rendered.HTMLBody,
		"token=test&amp;source=email",
	) {
		t.Fatal("expected HTML-escaped verification URL")
	}

	if !strings.Contains(
		rendered.TextBody,
		"https://example.com/verify",
	) {
		t.Fatal("expected plain-text fallback")
	}
}

func TestVerificationMailerBuildsTokenLink(t *testing.T) {
	t.Parallel()

	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("create renderer: %v", err)
	}

	sender := &fakeMessageSender{
		domain: "example.com",
	}

	mailer, err := NewVerificationMailer(
		sender,
		renderer,
		"https://app.example.com/verify-email?source=identity",
	)
	if err != nil {
		t.Fatalf("create verification mailer: %v", err)
	}

	err = mailer.SendVerification(
		context.Background(),
		appoutbox.VerificationMessage{
			EventID:   emailTestEventID,
			Recipient: "user@example.com",
			TokenID:   emailTestTokenID,
			ExpiresAt: time.Now().Add(time.Hour),
		},
	)
	if err != nil {
		t.Fatalf("send verification email: %v", err)
	}

	if sender.message.To != "user@example.com" {
		t.Fatalf(
			"unexpected recipient %q",
			sender.message.To,
		)
	}

	if !strings.Contains(
		sender.message.HTMLBody,
		"token="+emailTestTokenID,
	) {
		t.Fatal("expected verification token in HTML link")
	}

	expectedMessageID :=
		"<" + emailTestEventID + "@example.com>"

	if sender.message.MessageID != expectedMessageID {
		t.Fatalf(
			"expected message ID %q, got %q",
			expectedMessageID,
			sender.message.MessageID,
		)
	}
}

func TestBuildMIMEMessageIncludesHTMLAlternative(
	t *testing.T,
) {
	t.Parallel()

	rawMessage, err := buildMIMEMessage(
		mail.Address{
			Name:    "Beexter",
			Address: "sender@example.com",
		},
		mail.Address{
			Address: "user@example.com",
		},
		Message{
			To:        "user@example.com",
			Subject:   "Xác minh email",
			TextBody:  "Plain text",
			HTMLBody:  "<html><body>HTML</body></html>",
			MessageID: "<event@example.com>",
		},
		time.Date(
			2026,
			time.July,
			30,
			4,
			0,
			0,
			0,
			time.UTC,
		),
	)
	if err != nil {
		t.Fatalf("build MIME message: %v", err)
	}

	message := string(rawMessage)

	expectedParts := []string{
		"Content-Type: multipart/alternative;",
		`Content-Type: text/plain; charset="UTF-8"`,
		`Content-Type: text/html; charset="UTF-8"`,
		"Message-ID: <event@example.com>",
	}

	for _, expected := range expectedParts {
		if !strings.Contains(message, expected) {
			t.Fatalf(
				"expected MIME message to contain %q",
				expected,
			)
		}
	}
}

func TestNewSMTPSenderRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	_, err := NewSMTPSender(
		SMTPConfig{},
		slog.New(
			slog.NewJSONHandler(io.Discard, nil),
		),
	)

	if err == nil {
		t.Fatal("expected SMTP config validation error")
	}
}

type fakeMessageSender struct {
	domain  string
	message Message
}

func (s *fakeMessageSender) Send(
	_ context.Context,
	message Message,
) error {
	s.message = message
	return nil
}

func (s *fakeMessageSender) MessageIDDomain() string {
	return s.domain
}
