package sandbox

import (
	"fmt"
	"io"
	"os"

	"github.com/safedep/dry/log"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/safedep/pmg/errcodes"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type profileShowOptions struct {
	resolved bool
	driver   string
	cwd      string
	home     string
	jsonOut  bool
}

func newProfileShowCommand(factory registryFactory) *cobra.Command {
	opts := &profileShowOptions{}

	cmd := &cobra.Command{
		Use:           "show <name>",
		Short:         "Show a sandbox profile (raw YAML, resolved policy, or driver-rendered)",
		Example:       "  pmg sandbox profile show npm-restrictive --resolved",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runProfileShow(cmd.OutOrStdout(), args[0], opts, factory)
			if err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return err
		},
	}

	cmd.Flags().BoolVar(&opts.resolved, "resolved", false, "Print the policy after inheritance and variable expansion")
	cmd.Flags().StringVar(&opts.driver, "driver", "", "Render the resolved policy for a specific driver: seatbelt|bubblewrap|landlock")
	cmd.Flags().StringVar(&opts.cwd, "cwd", "", "Override ${CWD} during expansion (defaults to current working directory)")
	cmd.Flags().StringVar(&opts.home, "home", "", "Override ${HOME} during expansion (defaults to current user home)")
	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "Emit output as JSON")
	return cmd
}

func runProfileShow(out io.Writer, name string, opts *profileShowOptions, factory registryFactory) error {
	if err := validateDriver(opts.driver); err != nil {
		return err
	}

	registry, err := factory()
	if err != nil {
		return registryInitError(err)
	}

	if opts.driver != "" {
		return runProfileShowDriver(out, name, opts, registry)
	}

	if opts.resolved {
		return runProfileShowResolved(out, name, opts, registry)
	}

	return runProfileShowRaw(out, name, opts, registry)
}

func runProfileShowRaw(out io.Writer, name string, opts *profileShowOptions, registry pmgsandbox.ProfileRegistry) error {
	source, path, data, err := loadProfileSource(name, registry)
	if err != nil {
		return profileLoadError(err)
	}

	if opts.jsonOut {
		report := map[string]any{
			"name":   name,
			"source": string(source),
			"path":   path,
			"yaml":   string(data),
		}
		return writeJSONIndent(out, report)
	}

	_, err = out.Write(data)
	return err
}

func runProfileShowResolved(out io.Writer, name string, opts *profileShowOptions, registry pmgsandbox.ProfileRegistry) error {
	policy, err := registry.ResolveProfile(name, pmgsandbox.ResolveOptions{
		CWD:  opts.cwd,
		Home: opts.home,
	})
	if err != nil {
		return profileLoadError(err)
	}

	if opts.jsonOut {
		report := map[string]any{
			"name":   name,
			"policy": policy,
		}
		return writeJSONIndent(out, report)
	}

	data, err := yaml.Marshal(policy)
	if err != nil {
		return wrapUseful(fmt.Errorf("failed to marshal resolved policy: %w", err),
			errcodes.Unknown,
			"Failed to marshal the resolved policy to YAML. Re-run with --verbose for the underlying cause.")
	}

	_, err = out.Write(data)
	return err
}

func runProfileShowDriver(out io.Writer, name string, opts *profileShowOptions, registry pmgsandbox.ProfileRegistry) error {
	policy, err := registry.ResolveProfile(name, pmgsandbox.ResolveOptions{
		CWD:  opts.cwd,
		Home: opts.home,
	})
	if err != nil {
		return profileLoadError(err)
	}

	rendered, err := platform.Render(pmgsandbox.DriverName(opts.driver), policy)
	if err != nil {
		return wrapUseful(err, errcodes.InvalidArgument,
			"Could not render the policy for the requested driver. Verify the driver is supported on this host.")
	}

	if opts.jsonOut {
		report := map[string]any{
			"name":     name,
			"driver":   opts.driver,
			"rendered": string(rendered),
		}
		return writeJSONIndent(out, report)
	}

	_, err = out.Write(rendered)
	return err
}

func loadProfileSource(name string, registry pmgsandbox.ProfileRegistry) (pmgsandbox.ProfileSource, string, []byte, error) {
	if data, ok := registry.BuiltinProfileYAML(name); ok {
		return pmgsandbox.ProfileSourceBuiltin, "", data, nil
	}

	summaries, err := registry.ListProfiles()
	if err != nil {
		log.Warnf("sandbox: failed to enumerate user profiles: %v", err)
	}
	for _, s := range summaries {
		if s.Source == pmgsandbox.ProfileSourceUser && s.Name == name {
			data, readErr := os.ReadFile(s.Path)
			if readErr != nil {
				return "", "", nil, fmt.Errorf("failed to read user profile %s: %w", s.Path, readErr)
			}
			return pmgsandbox.ProfileSourceUser, s.Path, data, nil
		}
	}

	if data, readErr := os.ReadFile(name); readErr == nil {
		return pmgsandbox.ProfileSourceUser, name, data, nil
	}

	return "", "", nil, notFoundError(
		fmt.Sprintf("sandbox profile not found: %s", name),
		"Use `pmg sandbox profile list` to see available profiles, or pass an existing profile YAML path.",
	)
}
