package emaildelivery

import (
	"context"
	"strings"
	"testing"
	"time"

	appoutbox "github.com/DoMinhHHung/beexter/service/identity/internal/application/outbox"
)

const (
	passwordResetEventID = "0198f124-659f-7cbd-a441-dc7eea175081"
	passwordResetTokenID = "0198f124-659f-7cbd-a441-dc7eea175082"
)

func TestPasswordResetCatalogSupportsEmbeddedLocales(t *testing.T) {
	t.Parallel()

	catalog, err := NewPasswordResetCatalog()
	if err != nil {
		t.Fatalf("create password-reset catalog: %v", err)
	}

	locale, translation, err := catalog.Lookup("ja-JP")
	if err != nil {
		t.Fatalf("lookup Japanese translation: %v", err)
	}
	if locale != "ja" {
		t.Fatalf("expected locale ja, got %q", locale)
	}
	if translation.ButtonText == "" {
		t.Fatal("expected translated button text")
	}

	locale, _, err = catalog.Lookup("fr")
	if err != nil {
		t.Fatalf("lookup fallback translation: %v", err)
	}
	if locale != "en" {
		t.Fatalf("expected fallback locale en, got %q", locale)
	}
}

func TestPasswordResetMailerBuildsLocalizedHTML(t *testing.T) {
	t.Parallel()

	catalog, err := NewPasswordResetCatalog()
	if err != nil {
		t.Fatalf("create catalog: %v", err)
	}
	renderer, err := NewRenderer()
	if err != nil {
		t.Fatalf("create renderer: %v", err)
	}

	sender := &passwordResetFakeSender{domain: "example.com"}
	mailer, err := NewPasswordResetMailer(
		sender,
		renderer,
		catalog,
		"https://app.example.com/reset-password?source=identity",
	)
	if err != nil {
		t.Fatalf("create password-reset mailer: %v", err)
	}
	mailer.now = func() time.Time {
		return time.Date(2026, time.July, 30, 0, 0, 0, 0, time.UTC)
	}

	err = mailer.SendPasswordReset(
		context.Background(),
		appoutbox.PasswordResetMessage{
			EventID:   passwordResetEventID,
			Recipient: "user@example.com",
			TokenID:   passwordResetTokenID,
			ExpiresAt: time.Date(2026, time.July, 30, 8, 0, 0, 0, time.UTC),
			Locale:    "vi",
		},
	)
	if err != nil {
		t.Fatalf("send password-reset email: %v", err)
	}

	if sender.message.Subject != "Đặt lại mật khẩu BeexSter" {
		t.Fatalf("unexpected subject %q", sender.message.Subject)
	}
	if !strings.Contains(sender.message.HTMLBody, "Đặt lại mật khẩu") {
		t.Fatal("expected Vietnamese HTML content")
	}
	if !strings.Contains(sender.message.HTMLBody, "token="+passwordResetTokenID) {
		t.Fatal("expected token in password-reset URL")
	}
	if sender.message.MessageID != "<"+passwordResetEventID+"@example.com>" {
		t.Fatalf("unexpected Message-ID %q", sender.message.MessageID)
	}
}

type passwordResetFakeSender struct {
	domain  string
	message Message
}

func (s *passwordResetFakeSender) Send(
	_ context.Context,
	message Message,
) error {
	s.message = message
	return nil
}

func (s *passwordResetFakeSender) MessageIDDomain() string {
	return s.domain
}
