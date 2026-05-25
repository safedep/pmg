package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

const ExitCodeProbeFailure = 2

var sandboxErrorExit = func(_ *cobra.Command, err error) error {
	type exitCoder interface{ ExitCode() int }
	if ec, ok := err.(exitCoder); ok {
		ui.ErrorExitWithCode(err, ec.ExitCode())
		return nil
	}

	ui.ErrorExit(err)
	return nil
}

var validDrivers = map[pmgsandbox.DriverName]struct{}{
	pmgsandbox.DriverSeatbelt:   {},
	pmgsandbox.DriverBubblewrap: {},
	pmgsandbox.DriverLandlock:   {},
}

func validateDriver(name string) error {
	if name == "" {
		return nil
	}
	if _, ok := validDrivers[pmgsandbox.DriverName(name)]; !ok {
		return invalidArgumentError(
			fmt.Sprintf("unknown driver %q", name),
			"Use one of: seatbelt, bubblewrap, landlock",
		)
	}
	return nil
}

func invalidArgumentError(message, help string) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidArgument).
		WithHumanError(message).
		WithHelp(help).
		Wrap(errors.New(message))
}

func notFoundError(message, help string) error {
	return usefulerror.NewUsefulError().
		WithCode(errcodes.NotFound).
		WithHumanError(message).
		WithHelp(help).
		Wrap(errors.New(message))
}

// Idempotent: returns err unchanged when nil or already useful, so call
// sites can apply it without losing more precise pre-classified errors.
func wrapUseful(err error, code, help string) error {
	if err == nil {
		return nil
	}
	if hasUsefulError(err) {
		return err
	}
	return usefulerror.NewUsefulError().
		WithCode(code).
		WithHumanError(err.Error()).
		WithHelp(help).
		Wrap(err)
}

func profileLoadError(err error) error {
	if err == nil {
		return nil
	}
	if hasUsefulError(err) {
		return err
	}
	switch {
	case errors.Is(err, pmgsandbox.ErrProfileNotFound):
		return wrapUseful(err, errcodes.NotFound,
			"Use `pmg sandbox profile list` to see available profiles, or pass an existing profile YAML path.")
	case errors.Is(err, pmgsandbox.ErrProfileInvalid):
		return wrapUseful(err, errcodes.InvalidArgument,
			"Check the profile YAML for syntax/schema issues and verify any 'inherits:' parent name.")
	}
	return wrapUseful(err, errcodes.Unknown,
		"Failed to load the sandbox profile. Run with --verbose for the underlying cause.")
}

func hasUsefulError(err error) bool {
	// AsUsefulError also runs global converters for plain errors like
	// fs.ErrPermission. Contextual wrappers must only skip errors that already
	// carry UsefulError details, otherwise generic converters hide command help.
	var usefulErr usefulerror.UsefulError
	return errors.As(err, &usefulErr)
}

func registryInitError(err error) error {
	return wrapUseful(err, ioErrorCode(err, errcodes.Unknown),
		"Failed to initialise the sandbox profile registry. Run with --verbose for details.")
}

func ioErrorCode(err error, fallback string) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return errcodes.PermissionDenied
	case errors.Is(err, fs.ErrNotExist):
		return errcodes.NotFound
	}
	return fallback
}

func writeJSONIndent(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func renderTable(out io.Writer, rows [][]string, after func(rowIdx int) error) error {
	return ui.RenderTable(out, rows, after)
}

func firstColumnIndent(rows [][]string) string {
	return ui.FirstColumnIndent(rows)
}

func truncate(s string, n int) string {
	return ui.Truncate(s, n)
}

func truncateLeft(s string, n int) string {
	return ui.TruncateLeft(s, n)
}
