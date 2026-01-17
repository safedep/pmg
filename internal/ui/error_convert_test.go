package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/safedep/pmg/usefulerror"
	"github.com/stretchr/testify/assert"
)

func Test_convertToUsefulError(t *testing.T) {
	tests := []struct {
		name           string
		inputError     error
		wantCode       string
		wantHumanError string
		wantContains   string
		wantNil        bool
	}{
		{
			name: "AlreadyUseful",
			inputError: usefulerror.Useful().
				WithCode("CUSTOM").
				WithHumanError("Already useful").
				Msg("test"),
			wantCode:       "CUSTOM",
			wantHumanError: "Already useful",
		},
		{
			name:         "FileNotExist",
			inputError:   &fs.PathError{Op: "open", Path: "/nonexistent/file.txt", Err: os.ErrNotExist},
			wantCode:     ErrCodeNotExist,
			wantContains: "/nonexistent/file.txt",
		},
		{
			name:         "PermissionDenied",
			inputError:   &fs.PathError{Op: "open", Path: "/root/secret", Err: os.ErrPermission},
			wantCode:     ErrCodePermission,
			wantContains: "/root/secret",
		},
		{
			name:         "ContextTimeout",
			inputError:   context.DeadlineExceeded,
			wantCode:     ErrCodeTimeout,
			wantContains: "timed out",
		},
		{
			name:         "ContextCanceled",
			inputError:   context.Canceled,
			wantCode:     ErrCodeCanceled,
			wantContains: "canceled",
		},
		{
			name:       "UnexpectedEOF",
			inputError: io.ErrUnexpectedEOF,
			wantCode:   ErrCodeUnexpectedEOF,
		},
		{
			name:       "WrappedError",
			inputError: fmt.Errorf("failed to read config: %w", os.ErrNotExist),
			wantCode:   ErrCodeNotExist,
		},
		{
			name:           "UnknownError",
			inputError:     errors.New("some unknown error"),
			wantCode:       ErrCodeUnknown,
			wantHumanError: "some unknown error",
		},
		{
			name: "UnknownWrappedError",
			inputError: fmt.Errorf("more context: %w",
				fmt.Errorf("outer context: %w",
					errors.New("root cause error"))),
			wantCode:       ErrCodeUnknown,
			wantHumanError: "root cause error",
		},
		{
			name:       "Nil",
			inputError: nil,
			wantNil:    true,
		},
		{
			name:       "NetworkErrorMessage",
			inputError: errors.New("connection refused"),
			wantCode:   ErrCodeNetwork,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertToUsefulError(tt.inputError)

			if tt.wantNil {
				assert.Nil(t, result)
				return
			}

			assert.NotNil(t, result)
			assert.Equal(t, tt.wantCode, result.Code())

			if tt.wantHumanError != "" {
				assert.Equal(t, tt.wantHumanError, result.HumanError())
			}

			if tt.wantContains != "" {
				assert.Contains(t, result.HumanError(), tt.wantContains)
			}
		})
	}
}

func TestExtractPathFromError(t *testing.T) {
	tests := []struct {
		name     string
		inputErr error
		wantPath string
	}{
		{
			name:     "PathError",
			inputErr: &fs.PathError{Op: "open", Path: "/some/path", Err: os.ErrNotExist},
			wantPath: "/some/path",
		},
		{
			name:     "LinkError",
			inputErr: &os.LinkError{Op: "link", Old: "/old/path", New: "/new/path", Err: os.ErrPermission},
			wantPath: "/old/path",
		},
		{
			name:     "generic error",
			inputErr: errors.New("some error"),
			wantPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := extractPathFromError(tt.inputErr)
			assert.Equal(t, tt.wantPath, path)
		})
	}
}
