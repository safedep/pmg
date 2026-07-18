package sandbox

import (
	"errors"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

// presetRegistryFactory builds a PresetRegistry. Tests inject a stub.
type presetRegistryFactory func() (pmgsandbox.PresetRegistry, error)

func defaultPresetRegistryFactory() (pmgsandbox.PresetRegistry, error) {
	return pmgsandbox.NewPresetRegistry(
		pmgsandbox.WithUserPresetDir(config.Get().SandboxPresetDir()),
	)
}

// NewPresetCommand returns the `pmg sandbox preset` parent command.
func NewPresetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "preset",
		Short: "Discover and inspect sandbox presets (workload allowance bundles)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newPresetListCommand(defaultPresetRegistryFactory))
	cmd.AddCommand(newPresetShowCommand(defaultPresetRegistryFactory))
	cmd.AddCommand(newPresetLintCommand())
	return cmd
}

func presetRegistryError(err error) error {
	return wrapUseful(err, errcodes.Unknown,
		"Failed to initialise the sandbox preset registry. Run with --verbose for details.")
}

func presetLoadError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, pmgsandbox.ErrPresetNotFound):
		return wrapUseful(err, errcodes.NotFound,
			"Use `pmg sandbox preset list` to see available presets.")
	case errors.Is(err, pmgsandbox.ErrPresetInvalid):
		return wrapUseful(err, errcodes.InvalidArgument,
			"Check the preset YAML against docs/sandbox-presets.md and run `pmg sandbox preset lint <file>`.")
	}
	return wrapUseful(err, errcodes.Unknown,
		"Failed to load the sandbox preset. Run with --verbose for the underlying cause.")
}
