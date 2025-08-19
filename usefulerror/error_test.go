package usefulerror

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUsefulErrorBuilder_Error(t *testing.T) {
	tests := []struct {
		name     string
		builder  func() *usefulErrorBuilder
		expected string
	}{
		{
			name: "with original error",
			builder: func() *usefulErrorBuilder {
				return Useful().Wrap(errors.New("original error"))
			},
			expected: "original error",
		},
		{
			name: "with msg only",
			builder: func() *usefulErrorBuilder {
				return Useful().Msg("test message")
			},
			expected: "test message",
		},
		{
			name: "with code and msg",
			builder: func() *usefulErrorBuilder {
				return Useful().WithCode("TEST001").Msg("test message")
			},
			expected: "TEST001: test message",
		},
		{
			name: "with code only",
			builder: func() *usefulErrorBuilder {
				return Useful().WithCode("TEST001")
			},
			expected: "unknown error",
		},
		{
			name: "empty builder",
			builder: func() *usefulErrorBuilder {
				return Useful()
			},
			expected: "unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.builder()
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestUsefulErrorBuilder_HumanError(t *testing.T) {
	tests := []struct {
		name     string
		builder  func() *usefulErrorBuilder
		expected string
	}{
		{
			name: "with human error set",
			builder: func() *usefulErrorBuilder {
				return Useful().WithHumanError("Something went wrong")
			},
			expected: "Something went wrong",
		},
		{
			name: "empty human error",
			builder: func() *usefulErrorBuilder {
				return Useful()
			},
			expected: "An error occurred, but no human-readable message is available.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.builder()
			assert.Equal(t, tt.expected, err.HumanError())
		})
	}
}

func TestUsefulErrorBuilder_Help(t *testing.T) {
	tests := []struct {
		name     string
		builder  func() *usefulErrorBuilder
		expected string
	}{
		{
			name: "with help set",
			builder: func() *usefulErrorBuilder {
				return Useful().WithHelp("Try running with --verbose flag")
			},
			expected: "Try running with --verbose flag",
		},
		{
			name: "empty help",
			builder: func() *usefulErrorBuilder {
				return Useful()
			},
			expected: "No additional help is available for this error.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.builder()
			assert.Equal(t, tt.expected, err.Help())
		})
	}
}

func TestUsefulErrorBuilder_AdditionalHelp(t *testing.T) {
	tests := []struct {
		name     string
		builder  func() *usefulErrorBuilder
		expected string
	}{
		{
			name: "with additional help set",
			builder: func() *usefulErrorBuilder {
				return Useful().WithAdditionalHelp("Use --force to override")
			},
			expected: "Use --force to override",
		},
		{
			name: "empty additional help",
			builder: func() *usefulErrorBuilder {
				return Useful()
			},
			expected: "No additional help is available for this error.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.builder()
			assert.Equal(t, tt.expected, err.AdditionalHelp())
		})
	}
}

func TestUsefulErrorBuilder_Code(t *testing.T) {
	tests := []struct {
		name     string
		builder  func() *usefulErrorBuilder
		expected string
	}{
		{
			name: "with code set",
			builder: func() *usefulErrorBuilder {
				return Useful().WithCode("ERR001")
			},
			expected: "ERR001",
		},
		{
			name: "empty code",
			builder: func() *usefulErrorBuilder {
				return Useful()
			},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.builder()
			assert.Equal(t, tt.expected, err.Code())
		})
	}
}

func TestUsefulErrorBuilder_ChainedMethods(t *testing.T) {
	err := Useful().
		WithCode("TEST001").
		Msg("test message").
		WithHumanError("User friendly error").
		WithHelp("Try this fix").
		WithAdditionalHelp("Or try this")

	assert.Equal(t, "TEST001: test message", err.Error())
	assert.Equal(t, "User friendly error", err.HumanError())
	assert.Equal(t, "Try this fix", err.Help())
	assert.Equal(t, "Or try this", err.AdditionalHelp())
	assert.Equal(t, "TEST001", err.Code())
}

func TestAsUsefulError(t *testing.T) {
	tests := []struct {
		name        string
		input       error
		expectOk    bool
		expectError bool
	}{
		{
			name:        "nil error",
			input:       nil,
			expectOk:    false,
			expectError: false,
		},
		{
			name:        "useful error builder",
			input:       Useful().Msg("test"),
			expectOk:    true,
			expectError: false,
		},
		{
			name:        "regular error",
			input:       errors.New("regular error"),
			expectOk:    false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := AsUsefulError(tt.input)
			assert.Equal(t, tt.expectOk, ok)
			if tt.expectOk {
				assert.NotNil(t, result)
				assert.Implements(t, (*UsefulError)(nil), result)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestUsefulErrorBuilder_ImplementsUsefulError(t *testing.T) {
	var _ UsefulError = (*usefulErrorBuilder)(nil)

	builder := Useful()
	assert.Implements(t, (*UsefulError)(nil), builder)
}

func TestUsefulErrorBuilder_Wrap(t *testing.T) {
	originalErr := errors.New("original error")
	wrappedErr := Useful().Wrap(originalErr)

	assert.Equal(t, "original error", wrappedErr.Error())
	assert.Equal(t, "An error occurred, but no human-readable message is available.", wrappedErr.HumanError())
}

func TestUsefulErrorBuilder_ComplexScenario(t *testing.T) {
	originalErr := errors.New("file not found")

	err := Useful().
		Wrap(originalErr).
		WithCode("FILE001").
		WithHumanError("The configuration file could not be found").
		WithHelp("Make sure the config file exists in the current directory").
		WithAdditionalHelp("Use --config flag to specify a different location")

	assert.Equal(t, "file not found", err.Error())
	assert.Equal(t, "The configuration file could not be found", err.HumanError())
	assert.Equal(t, "Make sure the config file exists in the current directory", err.Help())
	assert.Equal(t, "Use --config flag to specify a different location", err.AdditionalHelp())
	assert.Equal(t, "FILE001", err.Code())

	usefulErr, ok := AsUsefulError(err)
	assert.True(t, ok)
	assert.Equal(t, err, usefulErr)
}
