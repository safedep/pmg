package usefulerror

import (
	"errors"
	"strings"
)

// UsefulError is an interface that can be implemented for custom error types
// that are actually useful for the user. Think of this as a way out of showing
// weird internal errors to the user, which actually don't help them
type UsefulError interface {
	// Error returns a string that is useful for the user.
	// Maintains compatibility with the standard error interface.
	Error() string

	// HumanError returns a string that is more human-readable.
	HumanError() string

	// Help returns a string that provides help or guidance specific to the
	// business logic of the error.
	Help() string

	// AdditionalHelp returns a string that provides additional help or guidance
	// This is useful for providing specific tooling related instructions such
	// as common line flags to use to fix the error.
	AdditionalHelp() string

	// Code returns a string that can be used to identify the error types
	// Meant for programmatic use, such as logging or categorization
	Code() string
}

type usefulErrorBuilder struct {
	originalError  error
	humanError     string
	help           string
	additionalHelp string
	code           string
	msg            string
}

var _ UsefulError = (*usefulErrorBuilder)(nil)

func Useful() *usefulErrorBuilder {
	return &usefulErrorBuilder{}
}

func (b *usefulErrorBuilder) Wrap(originalError error) *usefulErrorBuilder {
	b.originalError = originalError
	return b
}

// WithHumanError sets a string that is more human-readable.
func (b *usefulErrorBuilder) WithHumanError(humanError string) *usefulErrorBuilder {
	b.humanError = humanError
	return b
}

// WithHelp sets a string that provides additional help or guidance.
func (b *usefulErrorBuilder) WithHelp(help string) *usefulErrorBuilder {
	b.help = help
	return b
}

// WithCode sets a code that can be used to identify the error types.
func (b *usefulErrorBuilder) WithCode(code string) *usefulErrorBuilder {
	b.code = code
	return b
}

// WithMsg sets a message that is useful for the user, but not necessarily human-readable.
func (b *usefulErrorBuilder) Msg(msg string) *usefulErrorBuilder {
	b.msg = msg
	return b
}

// WithAdditionalHelp sets a string that provides additional help or guidance.
func (b *usefulErrorBuilder) WithAdditionalHelp(additionalHelp string) *usefulErrorBuilder {
	b.additionalHelp = additionalHelp
	return b
}

// Error implements the standard error interface, returning a string that is
func (b *usefulErrorBuilder) Error() string {
	if b.originalError != nil {
		return b.originalError.Error()
	}

	if b.msg == "" {
		return "unknown error"
	}

	msgParts := []string{}
	if b.code != "" {
		msgParts = append(msgParts, b.code)
	}

	if b.msg != "" {
		msgParts = append(msgParts, b.msg)
	}

	return strings.Join(msgParts, ": ")
}

// HumanError returns a string that is more human-readable.
func (b *usefulErrorBuilder) HumanError() string {
	if b.humanError == "" {
		return "An error occurred, but no human-readable message is available."
	}

	return b.humanError
}

// Help returns a string that provides additional help or guidance.
func (b *usefulErrorBuilder) Help() string {
	if b.help == "" {
		return "No additional help is available for this error."
	}

	return b.help
}

// Code returns a string that can be used to identify the error types.
func (b *usefulErrorBuilder) Code() string {
	if b.code == "" {
		return "unknown"
	}

	return b.code
}

// AdditionalHelp returns a string that provides additional help or guidance.
func (b *usefulErrorBuilder) AdditionalHelp() string {
	if b.additionalHelp == "" {
		return "No additional help is available for this error."
	}

	return b.additionalHelp
}

// AsUsefulError attempts to convert a given error into a UsefulError.
func AsUsefulError(err error) (UsefulError, bool) {
	if err == nil {
		return nil, false
	}

	var usefulErr *usefulErrorBuilder
	if errors.As(err, &usefulErr) {
		return usefulErr, true
	}

	if usefulErr, ok := err.(UsefulError); ok {
		return usefulErr, true
	}

	return nil, false
}
