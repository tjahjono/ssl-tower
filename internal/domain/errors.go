// Package domain holds the entities and the ports (interfaces) that the
// service layer depends on. It imports nothing from the outer layers.
package domain

import (
	"errors"
	"fmt"
)

// Sentinel errors the delivery layer maps onto HTTP status codes.
var (
	ErrNotFound = errors.New("resource not found")
	ErrConflict = errors.New("resource already exists")
	// ErrUnauthorized covers bad credentials, an expired session, or a wrong
	// TOTP/recovery code — deliberately generic so it never confirms which
	// half of a login attempt was wrong.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrForbidden means the request is authenticated but the account's role
	// doesn't permit this action.
	ErrForbidden = errors.New("forbidden")
)

// ValidationError reports user-correctable input problems.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// Invalid is a small constructor for ValidationError.
func Invalid(field, message string) error {
	return &ValidationError{Field: field, Message: message}
}

// AsValidation extracts a ValidationError from an error chain.
func AsValidation(err error) (*ValidationError, bool) {
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}
