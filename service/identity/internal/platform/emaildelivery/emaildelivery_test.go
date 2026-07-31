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

func TestCatalogLoadsEmbeddedLocales(t *testing.T) {
	t.Parallel()

	catalog, err := NewCatalog()
	if err != nil {
		t.Fatalf("create catalog: %v", err)
	}

	tests := []struct {
		requested string
		expected  string
		title     string
	}{
		{requested: "en-US", expected: "en", title: "Verify your email address"},
		{requested: "vi", expected: "vi", title: "Xác minh địa chỉ email"},
		{requested: "ja-JP", expected: "ja", title: "メールアドレスの確認"},
		{requested: "fr", expected: "en", title: "Verify your email address"},
	}

	for _, test := range tests {
		test := test

		t.Run(test.requested, func(t *testing.T) {
			t.Parallel()

			locale, translation, err := catalog.Lookup(test.requested)
			if err != nil {
				t.Fatalf("lookup translation: %v", err)
			}

			if locale != test.expected || translation.Title != test.title {
				t.Fatalf(
					"expected locale=%q title=%q, got locale=%q title=%q",
					test.expected,
					test.title,
					locale,
					translation.Title,
				)
			}
		})
	}
}

func TestRendererUsesLocalizedEmbeddedTemplate(t *testing.T) {
	t.Parallel()

	catalog, err := NewCatalog()
	if err != nil {
		t.Fatalf("create catalog: %v", err)
	}

	locale, translation, err := catalog.Lookup("ja")
	if err != nil {
		t.Fatalf("lookup translation: %v", err)
	}

	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("create renderer: %v", err)
	}

	rendered, err := renderer.RenderVerification(
		VerificationTemplateData{
			Locale:          locale,
			I18n:            translation,
			VerificationURL: "https://example.com/verify?token=test&source=email",
			ExpiresAt:       time.Date(2026, time.July, 30, 13, 0, 0, 0, time.UTC),
			CurrentYear:     2026,
		},
	)
	if err != nil {
		t.Fatalf("render verification email: %v", err)
	}

	expectedParts := []string{
		`<html lang="ja">`,
		"メールアドレスの確認",
		"メールを確認する",
		"token=test&amp;source=email",
		"© 2026 BeexSter",
	}

	for _, expected := range expectedParts {
		if !strings.Contains(rendered.HTMLBody, expected) {
			t.Fatalf("expected HTML to contain %q", expected)
		}
	}

	if rendered.Subject != "BeexSterのメールアドレスを確認してください" {
		t.Fatalf("unexpected subject %q", rendered.Subject)
	}
}

func TestVerificationMailerFallsBackToEnglish(t *testing.T) {
	t.Parallel()

	catalog, err := NewCatalog()
	if err != nil {
		t.Fatalf("create catalog: %v", err)
	}

	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("create renderer: %v", err)
	}

	sender := &fakeMessageSender{domain: "example.com"}
	mailer, err := NewVerificationMailer(
		sender,
		renderer,
		catalog,
		"https://app.example.com/verify-email",
	)
	if err != nil {
		t.Fatalf("create verification mailer: %v", err)
	}

	mailer.now = func() time.Time {
		return time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	}

	err = mailer.SendVerification(
		context.Background(),
		appoutbox.VerificationMessage{
			EventID:   emailTestEventID,
			Recipient: "user@example.com",
			TokenID:   emailTestTokenID,
			ExpiresAt: time.Date(2026, time.July, 30, 13, 0, 0, 0, time.UTC),
			Locale:    "fr",
		},
	)
	if err != nil {
		t.Fatalf("send verification email: %v", err)
	}

	if sender.message.Subject != "Verify your BeexSter email address" {
		t.Fatalf("unexpected fallback subject %q", sender.message.Subject)
	}

	if !strings.Contains(sender.message.HTMLBody, `<html lang="en">`) {
		t.Fatal("expected English fallback HTML")
	}

	if !strings.Contains(sender.message.HTMLBody, "token="+emailTestTokenID) {
		t.Fatal("expected verification token in HTML link")
	}
}

func TestBuildMIMEMessageIncludesHTMLAlternative(t *testing.T) {
	t.Parallel()

	rawMessage, err := buildMIMEMessage(
		mail.Address{
			Name:    "BeexSter",
			Address: "sender@example.com",
		},
		mail.Address{Address: "user@example.com"},
		Message{
			To:        "user@example.com",
			Subject:   "Verify email",
			TextBody:  "Plain text",
			HTMLBody:  "<html><body>HTML</body></html>",
			MessageID: "<event@example.com>",
		},
		time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("build MIME message: %v", err)
	}

	message := string(rawMessage)
	for _, expected := range []string{
		"Content-Type: multipart/alternative;",
		`Content-Type: text/plain; charset="UTF-8"`,
		`Content-Type: text/html; charset="UTF-8"`,
		"Message-ID: <event@example.com>",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("expected MIME message to contain %q", expected)
		}
	}
}

func TestNewSMTPSenderRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	_, err := NewSMTPSender(
		SMTPConfig{},
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
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
