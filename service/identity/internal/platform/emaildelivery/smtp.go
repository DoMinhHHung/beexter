package emaildelivery

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

var (
	ErrSMTPNotInitialized = errors.New(
		"SMTP sender is not initialized",
	)

	ErrInvalidSMTPConfig = errors.New(
		"SMTP configuration is invalid",
	)

	ErrInvalidEmailMessage = errors.New(
		"email message is invalid",
	)
)

type SMTPConfig struct {
	Host        string
	Port        int
	Username    string
	AppPassword string
	FromName    string
	FromAddress string
	Timeout     time.Duration
}

type Message struct {
	To        string
	Subject   string
	TextBody  string
	HTMLBody  string
	MessageID string
}

type SMTPSender struct {
	host            string
	address         string
	username        string
	appPassword     string
	from            mail.Address
	messageIDDomain string
	timeout         time.Duration
	logger          *slog.Logger
	now             func() time.Time
}

func NewSMTPSender(
	config SMTPConfig,
	logger *slog.Logger,
) (*SMTPSender, error) {
	if logger == nil {
		return nil, ErrSMTPNotInitialized
	}

	host := strings.TrimSpace(config.Host)
	username := strings.TrimSpace(config.Username)
	fromAddress := strings.TrimSpace(config.FromAddress)

	if host == "" ||
		config.Port < 1 ||
		config.Port > 65535 ||
		username == "" ||
		config.AppPassword == "" ||
		fromAddress == "" ||
		config.Timeout <= 0 {
		return nil, ErrInvalidSMTPConfig
	}

	if strings.ContainsAny(host, "\r\n") ||
		strings.ContainsAny(username, "\r\n") ||
		strings.ContainsAny(fromAddress, "\r\n") ||
		strings.ContainsAny(config.FromName, "\r\n") {
		return nil, ErrInvalidSMTPConfig
	}

	parsedFrom, err := mail.ParseAddress(fromAddress)
	if err != nil || parsedFrom.Address != fromAddress {
		return nil, fmt.Errorf(
			"%w: invalid from address",
			ErrInvalidSMTPConfig,
		)
	}

	atIndex := strings.LastIndex(parsedFrom.Address, "@")
	if atIndex <= 0 ||
		atIndex == len(parsedFrom.Address)-1 {
		return nil, fmt.Errorf(
			"%w: from address has no domain",
			ErrInvalidSMTPConfig,
		)
	}

	return &SMTPSender{
		host: host,
		address: net.JoinHostPort(
			host,
			strconv.Itoa(config.Port),
		),
		username:    username,
		appPassword: config.AppPassword,
		from: mail.Address{
			Name:    strings.TrimSpace(config.FromName),
			Address: parsedFrom.Address,
		},
		messageIDDomain: parsedFrom.Address[atIndex+1:],
		timeout:         config.Timeout,
		logger:          logger,
		now:             time.Now,
	}, nil
}

func (s *SMTPSender) MessageIDDomain() string {
	if s == nil {
		return ""
	}

	return s.messageIDDomain
}

func (s *SMTPSender) Send(
	ctx context.Context,
	message Message,
) error {
	if s == nil || s.logger == nil {
		return ErrSMTPNotInitialized
	}

	if ctx == nil {
		return ErrInvalidEmailMessage
	}

	recipient, err := parseRecipient(message.To)
	if err != nil {
		return err
	}

	rawMessage, err := buildMIMEMessage(
		s.from,
		recipient,
		message,
		s.now().UTC(),
	)
	if err != nil {
		return err
	}

	operationContext, cancelOperation := context.WithTimeout(
		ctx,
		s.timeout,
	)
	defer cancelOperation()

	dialer := &net.Dialer{}

	connection, err := dialer.DialContext(
		operationContext,
		"tcp",
		s.address,
	)
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}

	deadline, hasDeadline := operationContext.Deadline()
	if hasDeadline {
		if err := connection.SetDeadline(deadline); err != nil {
			closeErr := connection.Close()

			return errors.Join(
				fmt.Errorf(
					"set SMTP connection deadline: %w",
					err,
				),
				closeErr,
			)
		}
	}

	watchDone := make(chan struct{})

	go func() {
		select {
		case <-operationContext.Done():
			if err := connection.SetDeadline(time.Now()); err != nil {
				s.logger.Debug(
					"failed to interrupt SMTP connection",
					slog.String("error", err.Error()),
				)
			}

		case <-watchDone:
		}
	}()

	defer close(watchDone)

	client, err := smtp.NewClient(connection, s.host)
	if err != nil {
		closeErr := connection.Close()

		return errors.Join(
			fmt.Errorf("create SMTP client: %w", err),
			closeErr,
		)
	}

	clientClosed := false

	defer func() {
		if clientClosed {
			return
		}

		if err := client.Close(); err != nil {
			s.logger.Debug(
				"failed to close SMTP client",
				slog.String("error", err.Error()),
			)
		}
	}()

	supportsSTARTTLS, _ := client.Extension("STARTTLS")
	if !supportsSTARTTLS {
		return errors.New(
			"SMTP server does not support STARTTLS",
		)
	}

	if err := client.StartTLS(&tls.Config{
		ServerName: s.host,
		MinVersion: tls.VersionTLS12,
	}); err != nil {
		return fmt.Errorf("start SMTP TLS: %w", err)
	}

	auth := smtp.PlainAuth(
		"",
		s.username,
		s.appPassword,
		s.host,
	)

	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("authenticate SMTP client: %w", err)
	}

	if err := client.Mail(s.from.Address); err != nil {
		return fmt.Errorf("set SMTP sender: %w", err)
	}

	if err := client.Rcpt(recipient.Address); err != nil {
		return fmt.Errorf("set SMTP recipient: %w", err)
	}

	dataWriter, err := client.Data()
	if err != nil {
		return fmt.Errorf("open SMTP message writer: %w", err)
	}

	_, writeErr := dataWriter.Write(rawMessage)
	closeDataErr := dataWriter.Close()

	if writeErr != nil || closeDataErr != nil {
		return errors.Join(
			fmt.Errorf(
				"write SMTP message: %w",
				writeErr,
			),
			closeDataErr,
		)
	}

	if err := client.Quit(); err != nil {
		clientClosed = true

		s.logger.Warn(
			"SMTP server accepted message but QUIT failed",
			slog.String("error", err.Error()),
		)

		return nil
	}

	clientClosed = true

	return nil
}

func parseRecipient(rawRecipient string) (mail.Address, error) {
	recipient := strings.TrimSpace(rawRecipient)

	if recipient == "" ||
		strings.ContainsAny(recipient, "\r\n") {
		return mail.Address{}, ErrInvalidEmailMessage
	}

	parsedRecipient, err := mail.ParseAddress(recipient)
	if err != nil ||
		parsedRecipient.Address != recipient {
		return mail.Address{}, fmt.Errorf(
			"%w: invalid recipient",
			ErrInvalidEmailMessage,
		)
	}

	return mail.Address{
		Address: parsedRecipient.Address,
	}, nil
}

func buildMIMEMessage(
	from mail.Address,
	to mail.Address,
	message Message,
	now time.Time,
) ([]byte, error) {
	if err := validateHeaderValue(message.Subject); err != nil {
		return nil, err
	}

	if err := validateHeaderValue(message.MessageID); err != nil {
		return nil, err
	}

	if message.Subject == "" ||
		message.TextBody == "" ||
		message.HTMLBody == "" ||
		message.MessageID == "" {
		return nil, ErrInvalidEmailMessage
	}

	var multipartBody bytes.Buffer

	multipartWriter := multipart.NewWriter(&multipartBody)

	if err := writeAlternativePart(
		multipartWriter,
		`text/plain; charset="UTF-8"`,
		message.TextBody,
	); err != nil {
		return nil, err
	}

	if err := writeAlternativePart(
		multipartWriter,
		`text/html; charset="UTF-8"`,
		message.HTMLBody,
	); err != nil {
		return nil, err
	}

	if err := multipartWriter.Close(); err != nil {
		return nil, fmt.Errorf(
			"close MIME multipart writer: %w",
			err,
		)
	}

	var messageBuffer bytes.Buffer

	headers := []struct {
		Name  string
		Value string
	}{
		{Name: "From", Value: from.String()},
		{Name: "To", Value: to.String()},
		{
			Name: "Subject",
			Value: mime.QEncoding.Encode(
				"UTF-8",
				message.Subject,
			),
		},
		{
			Name:  "Date",
			Value: now.Format(time.RFC1123Z),
		},
		{
			Name:  "Message-ID",
			Value: message.MessageID,
		},
		{
			Name:  "MIME-Version",
			Value: "1.0",
		},
		{
			Name: "Content-Type",
			Value: fmt.Sprintf(
				`multipart/alternative; boundary=%q`,
				multipartWriter.Boundary(),
			),
		},
	}

	for _, header := range headers {
		if _, err := fmt.Fprintf(
			&messageBuffer,
			"%s: %s\r\n",
			header.Name,
			header.Value,
		); err != nil {
			return nil, fmt.Errorf(
				"write MIME header %s: %w",
				header.Name,
				err,
			)
		}
	}

	messageBuffer.WriteString("\r\n")

	if _, err := messageBuffer.Write(
		multipartBody.Bytes(),
	); err != nil {
		return nil, fmt.Errorf(
			"write MIME multipart body: %w",
			err,
		)
	}

	return messageBuffer.Bytes(), nil
}

func writeAlternativePart(
	writer *multipart.Writer,
	contentType string,
	body string,
) error {
	headers := make(textproto.MIMEHeader)
	headers.Set("Content-Type", contentType)
	headers.Set(
		"Content-Transfer-Encoding",
		"quoted-printable",
	)

	partWriter, err := writer.CreatePart(headers)
	if err != nil {
		return fmt.Errorf(
			"create MIME alternative part: %w",
			err,
		)
	}

	quotedPrintableWriter := quotedprintable.NewWriter(
		partWriter,
	)

	_, writeErr := io.WriteString(
		quotedPrintableWriter,
		body,
	)

	closeErr := quotedPrintableWriter.Close()

	if writeErr != nil || closeErr != nil {
		return errors.Join(
			fmt.Errorf(
				"write MIME alternative body: %w",
				writeErr,
			),
			closeErr,
		)
	}

	return nil
}

func validateHeaderValue(value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return ErrInvalidEmailMessage
	}

	return nil
}
