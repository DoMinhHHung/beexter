package domain

import "fmt"

type ErrorCode string

const (
	ErrInvalidInput       ErrorCode = "ERROR_INVALID_INPUT"
	ErrEmailAlreadyExists ErrorCode = "ERROR_EMAIL_ALREADY_EXISTS"
	ErrInvalidCredentials ErrorCode = "ERROR_INVALID_CREDENTIALS"
	ErrEmailNotVerified   ErrorCode = "ERROR_EMAIL_NOT_VERIFIED"
	ErrAccountInactive    ErrorCode = "ERROR_ACCOUNT_INACTIVE"
	ErrTokenInvalid       ErrorCode = "ERROR_TOKEN_INVALID"
	ErrTokenExpired       ErrorCode = "ERROR_TOKEN_EXPIRED"
	ErrTokenReuseDetected ErrorCode = "ERROR_TOKEN_REUSE_DETECTED"
	ErrNotFound           ErrorCode = "ERROR_NOT_FOUND"
	ErrForbidden          ErrorCode = "ERROR_FORBIDDEN"
	ErrRateLimited        ErrorCode = "ERROR_RATE_LIMITED"
	ErrInternal           ErrorCode = "ERROR_INTERNAL"
)

type Error struct {
	Code  ErrorCode
	Cause error
}

func NewError(code ErrorCode) *Error {
	return &Error{
		Code: code,
	}
}

func WrapError(code ErrorCode, cause error) *Error {
	return &Error{
		Code:  code,
		Cause: cause,
	}
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}

	if e.Cause == nil {
		return string(e.Code)
	}

	return fmt.Sprintf("%s: %v", e.Code, e.Cause)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Cause
}
