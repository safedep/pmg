package sandbox

import (
	"errors"
	"fmt"
	"io"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/ui"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/spf13/cobra"
)

// allowFactory bundles the dependencies needed by `pmg sandbox allow`. Tests
// inject stubs. Production wiring uses defaultAllowFactory.
type allowFactory struct {
	overlayDir func() string
	repoRoot   func() (string, error)
	cache      func() *pmgsandbox.ViolationCache
	locked     func() bool
}

func defaultAllowFactory() allowFactory {
	return allowFactory{
		overlayDir: func() string { return config.Get().SandboxOverlayDir() },
		repoRoot:   resolveCurrentRepoRoot,
		cache: func() *pmgsandbox.ViolationCache {
			return pmgsandbox.NewViolationCache(config.Get().SandboxViolationCacheDir())
		},
		locked: func() bool { return config.Get().IsLocked() },
	}
}

// NewAllowCommand returns the `pmg sandbox allow` command.
func NewAllowCommand() *cobra.Command {
	return newAllowCommand(defaultAllowFactory())
}

type allowOptions struct {
	last  bool
	all   bool
	force bool
}

func newAllowCommand(factory allowFactory) *cobra.Command {
	opts := &allowOptions{}

	cmd := &cobra.Command{
		Use:   "allow [type=value …]",
		Short: "Persist sandbox allowances for the current repository",
		Long: "Save allowances into the current repo's sandbox project overlay so future PMG runs in this repo apply them automatically.\n\n" +
			"Use --last to promote the primary violation from the most recent cached report,\n" +
			"or --last --all to promote every safe FS/exec violation from that report.\n" +
			"Manual entries (type=value …) accept any allow type and persist as-is.",
		Example: "  pmg sandbox allow write=./.astro net-bind=localhost:4321\n" +
			"  pmg sandbox allow --last --all",
		Args:          cobra.ArbitraryArgs,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runAllow(cmd.OutOrStdout(), args, opts, factory); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&opts.last, "last", false, "Promote allowances from the most recent cached violation report")
	cmd.Flags().BoolVar(&opts.all, "all", false, "With --last: promote every safe FS/exec violation (default: primary only)")
	cmd.Flags().BoolVar(&opts.force, "force", false, "Allow saving entries that touch sensitive paths (.env, .npmrc, .ssh, ...)")
	return cmd
}

func runAllow(out io.Writer, args []string, opts *allowOptions, factory allowFactory) error {
	// ApplySandbox ignores overlays under global_lockdown, so refuse up-front
	// instead of letting the user think their allowances took effect.
	if factory.locked != nil && factory.locked() {
		return usefulerror.NewUsefulError().
			WithCode(errcodes.PermissionDenied).
			WithHumanError("sandbox overlays are disabled while global_lockdown is in force").
			WithHelp("This machine's PMG configuration is locked. Contact your administrator to change sandbox policy.").
			Wrap(errors.New("sandbox overlay refused under global_lockdown"))
	}

	if !opts.last && len(args) == 0 {
		return invalidArgumentError(
			"nothing to save: pass type=value arguments or --last",
			"Example: `pmg sandbox allow write=./.astro` or `pmg sandbox allow --last --all`.",
		)
	}
	if opts.all && !opts.last {
		return invalidArgumentError(
			"--all requires --last",
			"Use `pmg sandbox allow --last --all` to promote every FS/exec violation from the most recent cached report.",
		)
	}

	repoRoot, err := factory.repoRoot()
	if err != nil {
		return wrapUseful(fmt.Errorf("resolve repo root: %w", err),
			errcodes.Unknown,
			"Could not determine the current repository root. Ensure the working directory is accessible.")
	}
	if repoRoot == "" {
		return invalidArgumentError(
			"could not determine current repository root",
			"Change to a directory inside the repository, then retry.",
		)
	}

	overlayDir := factory.overlayDir()
	if overlayDir == "" {
		return invalidArgumentError(
			"sandbox overlay directory is not configured",
			"Ensure the PMG config directory is writable, then retry.",
		)
	}

	overlay, _, err := pmgsandbox.LoadOverlayForRepo(overlayDir, repoRoot)
	if err != nil {
		return wrapUseful(err, errcodes.Unknown,
			"Could not read the existing project overlay. Check the file under SandboxOverlayDir().")
	}
	if overlay == nil {
		overlay = &pmgsandbox.Overlay{}
	}

	pending, err := collectAllowEntries(args, opts, factory)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return invalidArgumentError(
			"no eligible allowances to save",
			"Run a sandboxed command first to populate the violation cache, or pass explicit type=value arguments.",
		)
	}

	if err := guardSensitiveEntries(pending, opts.force); err != nil {
		return err
	}

	addedEntries := make([]pmgsandbox.OverlayAllow, 0, len(pending))
	for _, entry := range pending {
		if overlay.Add(entry) {
			addedEntries = append(addedEntries, entry)
		}
	}

	if len(addedEntries) == 0 {
		_, err := fmt.Fprintf(out, "%s\n", ui.Colors.Dim(fmt.Sprintf("No new allowances (%d already present).", len(pending))))
		return err
	}

	path, err := pmgsandbox.SaveOverlay(overlayDir, repoRoot, overlay)
	if err != nil {
		return wrapUseful(err, errcodes.Unknown,
			"Could not write the project overlay file. Check filesystem permissions for the overlay directory.")
	}

	if _, err := fmt.Fprintf(out, "%s Saved %d allowance(s) for %s\n", ui.Colors.Green("✓"), len(addedEntries), repoRoot); err != nil {
		return err
	}
	for _, e := range addedEntries {
		if _, err := fmt.Fprintf(out, "  %s %s=%s\n", ui.Colors.Dim("•"), e.Type, e.Value); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(out, "  %s %s\n", ui.Colors.Dim("overlay:"), ui.Colors.Dim(path))
	return err
}

func collectAllowEntries(args []string, opts *allowOptions, factory allowFactory) ([]pmgsandbox.OverlayAllow, error) {
	out := make([]pmgsandbox.OverlayAllow, 0, len(args)+1)

	for _, raw := range args {
		override, err := config.ParseSingleOverride(raw)
		if err != nil {
			return nil, invalidArgumentError(
				err.Error(),
				"Each positional argument must be `type=value` (read, write, exec, net-connect, net-bind).",
			)
		}
		out = append(out, pmgsandbox.OverlayAllow{Type: override.Type, Value: override.Value})
	}

	if !opts.last {
		return out, nil
	}

	suggestions, err := suggestionsFromCache(factory.cache(), opts.all)
	if err != nil {
		return nil, err
	}
	for _, sugg := range suggestions {
		typ := overrideTypeForKind(sugg.Kind)
		if typ == "" {
			continue
		}
		// Normalize through the manual-entry validator so stored values match
		// how applyRuntimeOverrides resolves them against the policy. Skip on
		// rejection so one bad target does not block the rest of the report.
		normalized, err := config.ParseSingleOverride(fmt.Sprintf("%s=%s", typ, sugg.Target))
		if err != nil {
			continue
		}
		out = append(out, pmgsandbox.OverlayAllow{Type: normalized.Type, Value: normalized.Value})
	}
	return out, nil
}

// suggestionsFromCache loads the latest cached violation report and returns
// the override suggestions to promote. When all is true, every safe FS/exec
// suggestion is returned, otherwise just the primary one (if any).
func suggestionsFromCache(cache *pmgsandbox.ViolationCache, all bool) ([]pmgsandbox.OverrideSuggestion, error) {
	entry, err := cache.Latest()
	if err != nil {
		return nil, wrapUseful(err, errcodes.Unknown,
			"Could not read the sandbox violation cache. Check the cache directory and retry.")
	}
	if entry == nil || entry.Record.Report == nil {
		return nil, notFoundError(
			"no cached violation report",
			"Run a sandboxed command that hits a denial first, then retry `pmg sandbox allow --last`.",
		)
	}

	if all {
		return pmgsandbox.BuildAllOverrides(entry.Record.Report), nil
	}
	if override := pmgsandbox.BuildExplanation(entry.Record.Report).Override; override != nil {
		return []pmgsandbox.OverrideSuggestion{*override}, nil
	}
	return nil, nil
}

// overrideTypeForKind maps a ViolationKind to the matching SandboxAllowType.
// Only FS + exec are handled; network kinds are not classified by drivers and
// will never reach this function via BuildAllOverrides.
func overrideTypeForKind(kind pmgsandbox.ViolationKind) config.SandboxAllowType {
	switch kind {
	case pmgsandbox.ViolationKindFSRead:
		return config.SandboxAllowRead
	case pmgsandbox.ViolationKindFSWrite, pmgsandbox.ViolationKindFSDeleteOrRename:
		return config.SandboxAllowWrite
	case pmgsandbox.ViolationKindExec:
		return config.SandboxAllowExec
	default:
		return ""
	}
}

func guardSensitiveEntries(entries []pmgsandbox.OverlayAllow, force bool) error {
	if force {
		return nil
	}
	for _, e := range entries {
		if pmgsandbox.IsSensitiveProjectTarget(e.Value) {
			return usefulerror.NewUsefulError().
				WithCode(errcodes.PermissionDenied).
				WithHumanError(fmt.Sprintf("refusing to allow sensitive target: %s", e.Value)).
				WithHelp("Re-run with --force to allow saving this entry, after verifying the path is intentional.").
				Wrap(errors.New("sensitive target"))
		}
	}
	return nil
}
