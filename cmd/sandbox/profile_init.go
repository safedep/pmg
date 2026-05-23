package sandbox

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/safedep/pmg/errcodes"
	"github.com/spf13/cobra"
)

// profileNameRe enforces a single path-safe segment. Rejects slashes,
// dot-prefixes, leading dashes, spaces, and other shell-hostile characters.
var profileNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

type profileInitOptions struct {
	from            string
	packageManagers []string
	description     string
}

func newProfileInitCommand(factory registryFactory) *cobra.Command {
	opts := &profileInitOptions{}

	cmd := &cobra.Command{
		Use:   "init <name>",
		Short: "Scaffold a new user sandbox profile",
		Long: "Create a starter YAML profile under the user profile directory.\n\n" +
			"Prefer --from <builtin> to emit a minimal child profile that inherits a built-in.\n" +
			"Copying the entire built-in YAML by hand is discouraged: the child stays small\n" +
			"and only declares its additive deltas.",
		Example:       "  pmg sandbox profile init my-npm --from npm-restrictive",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runProfileInit(cmd.OutOrStdout(), args[0], opts, factory)
			if err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return err
		},
	}

	cmd.Flags().StringVar(&opts.from, "from", "", "Built-in profile to inherit from (recommended)")
	cmd.Flags().StringSliceVar(&opts.packageManagers, "package-manager", nil, "Package manager this profile applies to (repeatable)")
	cmd.Flags().StringVar(&opts.description, "description", "", "One-line description for the profile")
	return cmd
}

func runProfileInit(out io.Writer, name string, opts *profileInitOptions, factory registryFactory) error {
	if !profileNameRe.MatchString(name) {
		return invalidArgumentError(
			fmt.Sprintf("invalid profile name %q", name),
			"Use a single path-safe name matching "+profileNameRe.String(),
		)
	}

	registry, err := factory()
	if err != nil {
		return registryInitError(err)
	}

	userDir := registry.UserProfileDir()
	if userDir == "" {
		return invalidArgumentError(
			"user profile directory is not configured",
			"Configure the sandbox profile directory, then retry `pmg sandbox profile init`.",
		)
	}

	if opts.from != "" {
		if _, ok := registry.BuiltinProfileYAML(opts.from); !ok {
			return notFoundError(
				fmt.Sprintf("unknown built-in profile %q", opts.from),
				"Use `pmg sandbox profile list` to see known built-in profiles.",
			)
		}
	}

	pms := opts.packageManagers
	placeholderPM := false
	if len(pms) == 0 {
		pms = []string{"npm"}
		placeholderPM = true
	}

	target := filepath.Join(userDir, name+".yml")
	if _, err := os.Stat(target); err == nil {
		return invalidArgumentError(
			fmt.Sprintf("profile already exists at %s", target),
			"Choose a different profile name, or edit the existing profile file to merge changes.",
		)
	} else if !os.IsNotExist(err) {
		return wrapUseful(fmt.Errorf("failed to stat %s: %w", target, err),
			ioErrorCode(err, errcodes.Unknown),
			"Could not stat the target profile path. Check the user profile directory permissions.")
	}

	if err := os.MkdirAll(userDir, 0o755); err != nil {
		return wrapUseful(fmt.Errorf("failed to create user profile directory %s: %w", userDir, err),
			ioErrorCode(err, errcodes.PermissionDenied),
			"Could not create the user profile directory. Check filesystem permissions for "+userDir+".")
	}

	content := renderScaffold(name, opts.description, opts.from, pms, placeholderPM)

	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		return wrapUseful(fmt.Errorf("failed to write %s: %w", target, err),
			ioErrorCode(err, errcodes.PermissionDenied),
			"Could not write the scaffolded profile. Check filesystem permissions for "+target+".")
	}

	_, err = fmt.Fprintln(out, target)
	return err
}

func renderScaffold(name, description, inheritsFrom string, pms []string, placeholderPM bool) string {
	var b strings.Builder

	b.WriteString("# pmg sandbox profile — scaffolded by `pmg sandbox profile init`.\n")
	b.WriteString("# Edit this file to fit your workflow, then validate with:\n")
	b.WriteString("#   pmg sandbox profile show ")
	b.WriteString(name)
	b.WriteString(" --resolved\n")
	b.WriteString("\n")

	b.WriteString("name: ")
	b.WriteString(name)
	b.WriteString("\n")
	if description != "" {
		b.WriteString("description: ")
		b.WriteString(yamlString(description))
		b.WriteString("\n")
	}

	if inheritsFrom != "" {
		b.WriteString("\n# Inherit from a built-in profile. Rules declared below are merged additively\n")
		b.WriteString("# over the parent — you do not need to repeat the parent's allow-lists.\n")
		b.WriteString("inherits: ")
		b.WriteString(inheritsFrom)
		b.WriteString("\n")
	}

	b.WriteString("\n# Package managers this profile applies to.")
	if placeholderPM {
		b.WriteString(" Placeholder — update to match your usage.")
	}
	b.WriteString("\npackage_managers:\n")
	for _, pm := range pms {
		b.WriteString("  - ")
		b.WriteString(pm)
		b.WriteString("\n")
	}

	b.WriteString("\n# Filesystem access — additive over the parent (if any).\n")
	b.WriteString("filesystem:\n")
	if inheritsFrom == "" {
		b.WriteString("  # Starter rule so the policy validates. Replace with the paths you actually need.\n")
		b.WriteString("  allow_read:\n")
		b.WriteString("    - ${CWD}/**\n")
	} else {
		b.WriteString("  allow_read: []\n")
	}
	b.WriteString("  allow_write: []\n")
	b.WriteString("  deny_read: []\n")
	b.WriteString("  deny_write: []\n")

	b.WriteString("\n# Network egress rules — additive over the parent (if any).\n")
	b.WriteString("# Patterns are \"host:port\"; use \"*:443\" or \"registry.npmjs.org:443\".\n")
	b.WriteString("network:\n")
	b.WriteString("  allow_outbound: []\n")
	b.WriteString("  deny_outbound: []\n")
	b.WriteString("  allow_bind: []\n")

	b.WriteString("\n# Process execution rules — additive over the parent (if any).\n")
	b.WriteString("process:\n")
	b.WriteString("  allow_exec: []\n")
	b.WriteString("  deny_exec: []\n")

	return b.String()
}

// yamlString quotes s for YAML when it contains characters that would otherwise
// confuse the parser. Plain scalars are emitted unquoted to keep the scaffold
// readable for hand-editing.
func yamlString(s string) string {
	if s == "" {
		return `""`
	}
	for _, r := range s {
		if r == ':' || r == '#' || r == '\'' || r == '"' || r == '\n' || r == '\t' {
			return fmt.Sprintf("%q", s)
		}
	}
	return s
}
