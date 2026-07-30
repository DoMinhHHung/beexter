package domain

import "fmt"

type ErrorCode string

const (
	ErrInvalidInput       ErrorCode = "ERR_INVALID_INPUT"
	ErrEmailAlreadyExists ErrorCode = "ERR_EMAIL_ALREADY_EXISTS"
	ErrInvalidCredentials ErrorCode = "ERR_INVALID_CREDENTIALS"
	ErrEmailNotVerified   ErrorCode = "ERR_EMAIL_NOT_VERIFIED"
	ErrAccountInactive    ErrorCode = "ERR_ACCOUNT_INACTIVE"
	ErrTokenInvalid       ErrorCode = "ERR_TOKEN_INVALID"
	ErrTokenExpired       ErrorCode = "ERR_TOKEN_EXPIRED"
	ErrTokenReuseDetected ErrorCode = "ERR_TOKEN_REUSE_DETECTED"
	ErrNotFound           ErrorCode = "ERR_NOT_FOUND"
	ErrForbidden          ErrorCode = "ERR_FORBIDDEN"
	ErrRateLimited        ErrorCode = "ERR_RATE_LIMITED"
	ErrInternal           ErrorCode = "ERR_INTERNAL"
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
