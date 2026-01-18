package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/safedep/pmg/usefulerror"
)

// errorMatcher defines how to detect and convert a specific error type
type errorMatcher struct {
	match   func(err error) bool
	convert func(err error) usefulerror.UsefulError
}

// errorMatchers is an ordered list of error matchers
// Order matters - more specific matchers should come first
var errorMatchers = []errorMatcher{
	// File not found errors
	{
		match: func(err error) bool {
			return errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrNotExist)
		},
		convert: func(err error) usefulerror.UsefulError {
			path := extractPathFromError(err)
			humanError := "File or directory not found"
			if path != "" {
				humanError = fmt.Sprintf("File or directory not found: %s", path)
			}

			return usefulerror.Useful().
				WithCode(usefulerror.ErrCodeNotFound).
				WithHumanError(humanError).
				WithHelp("Check if the path exists").
				WithAdditionalHelp("Use 'ls' to check directory contents").
				Wrap(err)
		},
	},
	// Permission denied errors
	{
		match: func(err error) bool {
			return errors.Is(err, os.ErrPermission) || errors.Is(err, fs.ErrPermission)
		},
		convert: func(err error) usefulerror.UsefulError {
			path := extractPathFromError(err)
			humanError := "Permission denied"
			if path != "" {
				humanError = fmt.Sprintf("Permission denied: %s", path)
			}
			return usefulerror.Useful().
				WithCode(usefulerror.ErrCodePermissionDenied).
				WithHumanError(humanError).
				WithHelp("Check permissions or use sudo").
				WithAdditionalHelp("Use 'ls -la' to check permissions").
				Wrap(err)
		},
	},
	// Process exit errors
	{
		match: func(err error) bool {
			var exitErr *exec.ExitError
			return errors.As(err, &exitErr)
		},
		convert: func(err error) usefulerror.UsefulError {
			var exitErr *exec.ExitError
			errors.As(err, &exitErr)
			exitCode := exitErr.ExitCode()
			return usefulerror.Useful().
				WithCode(usefulerror.ErrCodeLifecycle).
				WithHumanError(fmt.Sprintf("Command failed with exit code %d", exitCode)).
				WithHelp("Check command output above").
				Wrap(err)
		},
	},
	// Timeout errors (check before network errors since network timeouts also match)
	{
		match: func(err error) bool {
			return errors.Is(err, context.DeadlineExceeded)
		},
		convert: func(err error) usefulerror.UsefulError {
			return usefulerror.Useful().
				WithCode(usefulerror.ErrCodeTimeout).
				WithHumanError("Operation timed out").
				WithHelp("Try again or check your network").
				WithAdditionalHelp("Consider increasing timeout or retry later").
				Wrap(err)
		},
	},
	// Canceled errors
	{
		match: func(err error) bool {
			return errors.Is(err, context.Canceled)
		},
		convert: func(err error) usefulerror.UsefulError {
			return usefulerror.Useful().
				WithCode(usefulerror.ErrCodeCanceled).
				WithHumanError("Operation was canceled").
				Wrap(err)
		},
	},
	// Network errors
	{
		match: func(err error) bool {
			var netErr net.Error
			if errors.As(err, &netErr) {
				return true
			}
			// Also check for common network-related error messages
			errStr := err.Error()
			return strings.Contains(errStr, "connection refused") ||
				strings.Contains(errStr, "no such host") ||
				strings.Contains(errStr, "network is unreachable")
		},
		convert: func(err error) usefulerror.UsefulError {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return usefulerror.Useful().
					WithCode(usefulerror.ErrCodeTimeout).
					WithHumanError("Network request timed out").
					WithHelp("Check your internet connection").
					WithAdditionalHelp("Consider increasing timeout or retry later").
					Wrap(err)
			}
			return usefulerror.Useful().
				WithCode(usefulerror.ErrCodeNetwork).
				WithHumanError("Network error occurred").
				WithHelp("Check your internet connection").
				WithAdditionalHelp("The package registry may be temporarily unavailable").
				Wrap(err)
		},
	},
	// Unexpected EOF errors
	{
		match: func(err error) bool {
			return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		},
		convert: func(err error) usefulerror.UsefulError {
			return usefulerror.Useful().
				WithCode(usefulerror.ErrCodeUnexpectedEOF).
				WithHumanError("Unexpected end of data").
				WithHelp("Retry the download").
				WithAdditionalHelp("This may indicate network instability").
				Wrap(err)
		},
	},
}

// convertToUsefulError attempts to convert a regular error to a UsefulError
// by analyzing the error chain for known error types.
// Returns the original error wrapped in a generic UsefulError if no specific match is found.
func convertToUsefulError(err error) usefulerror.UsefulError {
	if err == nil {
		return nil
	}

	if ue, ok := usefulerror.AsUsefulError(err); ok {
		return ue
	}

	for _, matcher := range errorMatchers {
		if matcher.match(err) {
			return matcher.convert(err)
		}
	}

	return usefulerror.Useful().
		WithCode(usefulerror.ErrCodeUnknown).
		WithHumanError(extractRootCause(err)).
		WithHelp("An unexpected error occurred.").
		Wrap(err)
}

// extractRootCause traverses the error chain and returns the innermost error message.
// This provides a cleaner, more human-friendly message instead of the full error chain.
func extractRootCause(err error) string {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err.Error()
		}

		err = unwrapped
	}
}

// extractPathFromError attempts to extract a file path from path-related errors
func extractPathFromError(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Path
	}

	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return linkErr.Old
	}

	return ""
}
