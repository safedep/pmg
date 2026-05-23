package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"

	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
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
	if _, ok := usefulerror.AsUsefulError(err); ok {
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
	if _, ok := usefulerror.AsUsefulError(err); ok {
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

// renderTable prints rows with ANSI-aware column alignment. The first row is
// treated as a header. After each data row, optional continuation lines may be
// emitted via the after callback (passed the data row index; -1 for header).
func renderTable(out io.Writer, rows [][]string, after func(rowIdx int) error) error {
	if len(rows) == 0 {
		return nil
	}
	cols := len(rows[0])
	widths := make([]int, cols)
	for _, row := range rows {
		for i, cell := range row {
			if w := visibleWidth(cell); w > widths[i] {
				widths[i] = w
			}
		}
	}
	for rIdx, row := range rows {
		for i, cell := range row {
			if i == cols-1 {
				if _, err := fmt.Fprint(out, cell); err != nil {
					return err
				}
				continue
			}
			pad := widths[i] - visibleWidth(cell)
			if _, err := fmt.Fprint(out, cell, strings.Repeat(" ", pad+2)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
		if after != nil {
			dataIdx := rIdx - 1
			if err := after(dataIdx); err != nil {
				return err
			}
		}
	}
	return nil
}

// firstColumnIndent returns blanks the width of the first column plus the
// two-space padding renderTable uses, for continuation-line alignment.
func firstColumnIndent(rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}
	w := 0
	for _, row := range rows {
		if v := visibleWidth(row[0]); v > w {
			w = v
		}
	}
	return strings.Repeat(" ", w+2)
}

var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// visibleWidth returns the printable width of s with ANSI escape sequences
// stripped — text/tabwriter counts escape bytes as visible chars, misaligning
// colored cells.
func visibleWidth(s string) int {
	return len(ansiEscapeRe.ReplaceAllString(s, ""))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func truncateLeft(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[len(s)-n:]
	}
	return "..." + s[len(s)-(n-3):]
}
