package ratelimit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"

	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const minimumKeySecretLength = 32

var (
	ErrInvalidKeySecret = errors.New(
		"rate-limit key secret must contain at least 32 bytes",
	)

	ErrInvalidAction = errors.New(
		"rate-limit action is invalid",
	)

	ErrInvalidSubject = errors.New(
		"rate-limit subject is invalid",
	)
)

type Action string

const (
	ActionLogin              Action = "login"
	ActionSignup             Action = "signup"
	ActionForgotPassword     Action = "forgot_password"
	ActionResendVerification Action = "resend_verification"
	ActionResetPassword      Action = "reset_password"
	ActionChangePassword     Action = "change_password"
	ActionDeleteAccount      Action = "delete_account"
	ActionReactivation       Action = "reactivation"
)

func (a Action) IsValid() bool {
	switch a {
	case ActionLogin,
		ActionSignup,
		ActionForgotPassword,
		ActionResendVerification,
		ActionResetPassword,
		ActionChangePassword,
		ActionDeleteAccount,
		ActionReactivation:
		return true

	default:
		return false
	}
}

type KeyBuilder struct {
	secret []byte
}

func NewKeyBuilder(secret string) (*KeyBuilder, error) {
	if len(secret) < minimumKeySecretLength {
		return nil, ErrInvalidKeySecret
	}

	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)

	return &KeyBuilder{
		secret: secretCopy,
	}, nil
}

func (b *KeyBuilder) ForIP(
	action Action,
	ipAddress netip.Addr,
) (string, error) {
	if err := b.validate(action); err != nil {
		return "", err
	}

	if !ipAddress.IsValid() {
		return "", ErrInvalidSubject
	}

	ipAddress = ipAddress.Unmap()

	return fmt.Sprintf(
		"%s%s:ip:%s",
		rateLimitKeyPrefix,
		action,
		ipAddress.String(),
	), nil
}

func (b *KeyBuilder) ForEmail(
	action Action,
	rawEmail string,
) (string, error) {
	if err := b.validate(action); err != nil {
		return "", err
	}

	normalizedEmail, err := identity.NormalizeAndValidateEmail(
		rawEmail,
	)
	if err != nil {
		return "", fmt.Errorf(
			"%w: normalize email: %v",
			ErrInvalidSubject,
			err,
		)
	}

	emailDigest, err := b.hashSubject(normalizedEmail)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"%s%s:email:%s",
		rateLimitKeyPrefix,
		action,
		emailDigest,
	), nil
}

func (b *KeyBuilder) ForIdentity(
	action Action,
	identityID identity.ID,
) (string, error) {
	if err := b.validate(action); err != nil {
		return "", err
	}
	if identityID.IsZero() {
		return "", ErrInvalidSubject
	}

	identityDigest, err := b.hashSubject(identityID.String())
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"%s%s:identity:%s",
		rateLimitKeyPrefix,
		action,
		identityDigest,
	), nil
}

func (b *KeyBuilder) validate(action Action) error {
	if b == nil || len(b.secret) < minimumKeySecretLength {
		return ErrInvalidKeySecret
	}

	if !action.IsValid() {
		return ErrInvalidAction
	}

	return nil
}

func (b *KeyBuilder) hashSubject(subject string) (string, error) {
	hasher := hmac.New(sha256.New, b.secret)

	if _, err := hasher.Write([]byte(subject)); err != nil {
		return "", fmt.Errorf(
			"hash rate-limit subject: %w",
			err,
		)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
