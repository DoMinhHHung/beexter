package identity

import (
	"errors"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxEmailLength    = 254
	minPasswordLength = 8
	maxPasswordLength = 128
)

var (
	errEmailRequired       = errors.New("email is required")
	errEmailTooLong        = errors.New("email exceeds maximum length")
	errEmailInvalid        = errors.New("email format is invalid")
	errPasswordRequired    = errors.New("password is required")
	errPasswordInvalidUTF8 = errors.New("password contains invalid UTF-8")
	errPasswordTooShort    = errors.New("password is too short")
	errPasswordTooLong     = errors.New("password is too long")
	errPasswordUppercase   = errors.New("password requires an uppercase letter")
	errPasswordLowercase   = errors.New("password requires a lowercase letter")
	errPasswordDigit       = errors.New("password requires a digit")
	errPasswordSpecial     = errors.New("password requires a special character")
	errRoleInvalid         = errors.New("role is invalid")
)

type Role string

const (
	RoleClient    Role = "CLIENT"
	RoleJobSeeker Role = "JOB_SEEKER"
	RoleAgency    Role = "AGENCY"
	RoleAdmin     Role = "ADMIN"
	RoleViceAdmin Role = "VICE_ADMIN"
)

func NormalizeAndValidateEmail(rawEmail string) (string, error) {
	// Reject CR/LF before normalization.
	//
	// strings.TrimSpace removes these characters, so checking after trimming
	// would silently accept input such as "user@example.com\n".
	if strings.ContainsAny(rawEmail, "\r\n") {
		return "", errEmailInvalid
	}

	email := strings.ToLower(strings.TrimSpace(rawEmail))

	if email == "" {
		return "", errEmailRequired
	}

	if len(email) > maxEmailLength {
		return "", errEmailTooLong
	}

	parsedAddress, err := mail.ParseAddress(email)
	if err != nil {
		return "", errEmailInvalid
	}

	if parsedAddress.Address != email {
		return "", errEmailInvalid
	}

	return email, nil
}

func ValidatePassword(password string) error {
	if password == "" {
		return errPasswordRequired
	}

	if !utf8.ValidString(password) {
		return errPasswordInvalidUTF8
	}

	length := utf8.RuneCountInString(password)

	if length < minPasswordLength {
		return errPasswordTooShort
	}

	if length > maxPasswordLength {
		return errPasswordTooLong
	}

	var (
		hasUppercase bool
		hasLowercase bool
		hasDigit     bool
		hasSpecial   bool
	)

	for _, character := range password {
		switch {
		case unicode.IsUpper(character):
			hasUppercase = true

		case unicode.IsLower(character):
			hasLowercase = true

		case unicode.IsDigit(character):
			hasDigit = true

		case unicode.IsPunct(character), unicode.IsSymbol(character):
			hasSpecial = true
		}
	}

	if !hasUppercase {
		return errPasswordUppercase
	}

	if !hasLowercase {
		return errPasswordLowercase
	}

	if !hasDigit {
		return errPasswordDigit
	}

	if !hasSpecial {
		return errPasswordSpecial
	}

	return nil
}

func ParsePublicRole(rawRole string) (Role, error) {
	role := Role(strings.ToUpper(strings.TrimSpace(rawRole)))

	if !role.IsPublic() {
		return "", errRoleInvalid
	}

	return role, nil
}

func (r Role) IsValid() bool {
	switch r {
	case RoleClient,
		RoleJobSeeker,
		RoleAgency,
		RoleAdmin,
		RoleViceAdmin:
		return true

	default:
		return false
	}
}

func (r Role) IsPublic() bool {
	switch r {
	case RoleClient, RoleJobSeeker:
		return true

	default:
		return false
	}
}
