package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

var presetInitNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type presetInitOptions struct {
	description string
	author      string
	labels      []string
}

func newPresetInitCommand(dir func() string, factory presetRegistryFactory) *cobra.Command {
	opts := &presetInitOptions{}

	cmd := &cobra.Command{
		Use:   "init <name>",
		Short: "Scaffold a new user sandbox preset",
		Long: "Create a starter preset YAML under the user preset directory.\n\n" +
			"Presets are additive-only allowance bundles for one workload. Document the\n" +
			"residual risk of each allowance in threat-note comments: `preset show`\n" +
			"displays the YAML verbatim so users can review before applying.",
		Example:       "  pmg sandbox preset init myapp --author \"Your Name\" --label myapp --label dev-server",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPresetInit(cmd.OutOrStdout(), args[0], opts, dir, factory); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.description, "description", "", "One-line description of the workload")
	cmd.Flags().StringVar(&opts.author, "author", "", "Preset author shown in `preset list`")
	cmd.Flags().StringArrayVar(&opts.labels, "label", nil, "Metadata label for discovery (repeatable)")
	return cmd
}

func runPresetInit(out io.Writer, name string, opts *presetInitOptions, dir func() string, factory presetRegistryFactory) error {
	if !presetInitNameRe.MatchString(name) {
		return invalidArgumentError(
			fmt.Sprintf("invalid preset name %q", name),
			"Preset names are lowercase alphanumeric with dashes, e.g. my-app.",
		)
	}

	registry, err := factory()
	if err != nil {
		return presetRegistryError(err)
	}

	if info, err := registry.Get(name); err == nil && info.Source == pmgsandbox.PresetSourceBuiltin {
		return invalidArgumentError(
			fmt.Sprintf("%q is a built-in preset and cannot be shadowed", name),
			"Built-ins win name resolution. Choose a different name, or apply the built-in with `pmg sandbox allow preset="+name+"`.",
		)
	} else if err != nil && !errors.Is(err, pmgsandbox.ErrPresetNotFound) {
		return presetRegistryError(err)
	}

	userDir := dir()
	if userDir == "" {
		return invalidArgumentError(
			"user preset directory is not configured",
			"Ensure the PMG config directory is writable, then retry.",
		)
	}

	target := filepath.Join(userDir, name+".yml")
	if _, err := os.Stat(target); err == nil {
		return invalidArgumentError(
			fmt.Sprintf("preset already exists at %s", target),
			"Choose a different preset name, or edit the existing file.",
		)
	} else if !os.IsNotExist(err) {
		return wrapUseful(fmt.Errorf("failed to stat %s: %w", target, err),
			ioErrorCode(err, errcodes.Unknown),
			"Could not stat the target preset path. Check the user preset directory permissions.")
	}

	scaffold := renderPresetScaffold(name, opts)

	if preset, err := pmgsandbox.ParsePreset([]byte(scaffold)); err != nil {
		return wrapUseful(err, errcodes.Unknown, "Scaffold generation produced invalid YAML. Please report this bug.")
	} else if err := preset.Validate(); err != nil {
		return wrapUseful(err, errcodes.Unknown, "Scaffold generation produced an invalid preset. Please report this bug.")
	}

	if err := os.MkdirAll(userDir, 0o755); err != nil {
		return wrapUseful(fmt.Errorf("failed to create user preset directory %s: %w", userDir, err),
			ioErrorCode(err, errcodes.PermissionDenied),
			"Could not create the user preset directory. Check filesystem permissions for "+userDir+".")
	}

	if err := os.WriteFile(target, []byte(scaffold), 0o644); err != nil {
		return wrapUseful(fmt.Errorf("failed to write %s: %w", target, err),
			ioErrorCode(err, errcodes.PermissionDenied),
			"Could not write the scaffolded preset. Check filesystem permissions for "+target+".")
	}

	if _, err := fmt.Fprintln(out, target); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s\n%s\n%s\n",
		ui.Colors.Dim("Edit the file, then validate:  pmg sandbox preset lint "+target),
		ui.Colors.Dim("Review it:                     pmg sandbox preset show "+name),
		ui.Colors.Dim("Apply to a repo:               pmg sandbox allow preset="+name))
	return err
}

func renderPresetScaffold(name string, opts *presetInitOptions) string {
	var b strings.Builder

	b.WriteString("# pmg sandbox preset — scaffolded by `pmg sandbox preset init`.\n")
	b.WriteString("# Presets are additive-only: allowances on top of a hardened profile.\n")
	b.WriteString("# Deny rules, outbound network and env globs are rejected by design.\n\n")

	b.WriteString("schema_version: 1\nkind: preset\nname: ")
	b.WriteString(name)
	b.WriteString("\n")

	description := opts.description
	if description == "" {
		description = "What this preset enables, one line"
	}
	b.WriteString("description: ")
	b.WriteString(yamlString(description))
	b.WriteString("\n")

	b.WriteString("\nmetadata:\n")
	if opts.author != "" {
		b.WriteString("  author: ")
		b.WriteString(yamlString(opts.author))
		b.WriteString("\n")
	} else {
		b.WriteString("  # author: Your Name\n")
	}
	if len(opts.labels) > 0 {
		b.WriteString("  labels: [")
		b.WriteString(strings.Join(opts.labels, ", "))
		b.WriteString("]\n")
	} else {
		b.WriteString("  labels: [")
		b.WriteString(name)
		b.WriteString("]\n")
	}

	b.WriteString("\n# Threat notes: explain what each allowance permits and why the residual\n")
	b.WriteString("# risk is acceptable for this workload.\n")
	b.WriteString("filesystem:\n")
	b.WriteString("  # Starter rule so the preset validates. Replace with what the workload needs.\n")
	b.WriteString("  allow_write:\n")
	b.WriteString("    - ${CWD}/.")
	b.WriteString(name)
	b.WriteString("/**\n")
	b.WriteString("  # allow_read:\n")
	b.WriteString("  #   - ${CWD}/.cache/**\n")

	b.WriteString("\n# network:\n")
	b.WriteString("#   allow_bind:      # loopback only\n")
	b.WriteString("#     - localhost:8080\n")

	b.WriteString("\n# environment:\n")
	b.WriteString("#   allow:           # exact variable names, no globs\n")
	b.WriteString("#     - MYAPP_TELEMETRY_DISABLED\n")

	return b.String()
}
