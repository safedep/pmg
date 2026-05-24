package sandbox

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/safedep/pmg/errcodes"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const ExitCodeDiffError = 2

type profileDiffOptions struct {
	driver string
	cwd    string
	home   string
}

func newProfileDiffCommand(factory registryFactory) *cobra.Command {
	opts := &profileDiffOptions{}

	cmd := &cobra.Command{
		Use:           "diff <a> <b>",
		Short:         "Diff two resolved sandbox profiles (or their driver-rendered output)",
		Example:       "  pmg sandbox profile diff npm-restrictive pypi-restrictive",
		Args:          cobra.ExactArgs(2),
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runProfileDiff(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], args[1], opts, factory)
			if err != nil {
				if _, isDiff := err.(*diffPresentError); isDiff {
					cmd.SilenceErrors = true
					cmd.SilenceUsage = true
					return err
				}
				return sandboxErrorExit(cmd, err)
			}
			return err
		},
	}

	cmd.Flags().StringVar(&opts.driver, "driver", "", "Render each policy for a specific driver before diffing: seatbelt|bubblewrap|landlock")
	cmd.Flags().StringVar(&opts.cwd, "cwd", "", "Override ${CWD} during expansion (defaults to current working directory)")
	cmd.Flags().StringVar(&opts.home, "home", "", "Override ${HOME} during expansion (defaults to current user home)")
	return cmd
}

type diffPresentError struct{}

func (e *diffPresentError) Error() string { return "" }
func (e *diffPresentError) ExitCode() int { return 1 }

type diffOpError struct{ err error }

func (e *diffOpError) Error() string { return e.err.Error() }
func (e *diffOpError) Unwrap() error { return e.err }
func (e *diffOpError) ExitCode() int { return ExitCodeDiffError }

func runProfileDiff(out io.Writer, errOut io.Writer, nameA, nameB string, opts *profileDiffOptions, factory registryFactory) error {
	if err := validateDriver(opts.driver); err != nil {
		return &diffOpError{err: err}
	}

	registry, err := factory()
	if err != nil {
		return &diffOpError{err: registryInitError(err)}
	}

	dataA, err := materialize(registry, nameA, opts)
	if err != nil {
		return &diffOpError{err: err}
	}
	dataB, err := materialize(registry, nameB, opts)
	if err != nil {
		return &diffOpError{err: err}
	}

	if bytes.Equal(dataA, dataB) {
		if _, err := fmt.Fprintln(errOut, "profiles are identical"); err != nil {
			return &diffOpError{err: wrapUseful(err, errcodes.Unknown,
				"Failed to write diff output. Check that stderr is writable.")}
		}
		return nil
	}

	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(dataA)),
		B:        difflib.SplitLines(string(dataB)),
		FromFile: nameA,
		ToFile:   nameB,
		Context:  3,
	}
	text, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return &diffOpError{err: wrapUseful(fmt.Errorf("failed to render diff: %w", err),
			errcodes.Unknown,
			"Could not render the unified diff. Re-run with --verbose for the underlying cause.")}
	}

	if _, err := io.WriteString(out, text); err != nil {
		return &diffOpError{err: wrapUseful(err, errcodes.Unknown,
			"Failed to write diff output. Check that stdout is writable.")}
	}

	if !strings.HasSuffix(text, "\n") {
		if _, err := fmt.Fprintln(out); err != nil {
			return &diffOpError{err: wrapUseful(err, errcodes.Unknown,
				"Failed to write diff output. Check that stdout is writable.")}
		}
	}

	return &diffPresentError{}
}

func materialize(registry pmgsandbox.ProfileRegistry, name string, opts *profileDiffOptions) ([]byte, error) {
	policy, err := registry.ResolveProfile(name, pmgsandbox.ResolveOptions{
		CWD:  opts.cwd,
		Home: opts.home,
	})
	if err != nil {
		return nil, profileLoadError(err)
	}

	if opts.driver != "" {
		rendered, err := platform.Render(pmgsandbox.DriverName(opts.driver), policy)
		if err != nil {
			return nil, wrapUseful(err, errcodes.InvalidArgument,
				"Could not render the policy for the requested driver. Verify the driver is supported on this host.")
		}
		return rendered, nil
	}

	// Strip inherits since both sides are post-resolution.
	policy.Inherits = ""

	data, err := yaml.Marshal(policy)
	if err != nil {
		return nil, wrapUseful(fmt.Errorf("failed to marshal resolved policy %s: %w", name, err),
			errcodes.Unknown,
			"Failed to marshal the resolved policy to YAML. Re-run with --verbose for the underlying cause.")
	}
	return data, nil
}
