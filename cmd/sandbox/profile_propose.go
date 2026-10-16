package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/netobserve"
	"github.com/safedep/pmg/proxy/netpolicy"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/safedep/pmg/sandbox/propose"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	proposeSectionNetwork = "network"
	proposeDefaultWindow  = "30d"

	// proposeDaemonParent is the built-in a proposal from a daemon run
	// inherits. The daemon serves every package manager, so no single
	// package manager profile fits.
	proposeDaemonParent = "exec"
)

type profileProposeOptions struct {
	section string
	run     string
	last    bool
	since   string
	newRef  string
	into    string
	dryRun  bool
	json    bool
}

// proposeDeps are the seams the tests replace: where the event log is, the
// repository the command runs in, and the clock.
type proposeDeps struct {
	eventLogDir func() (string, error)
	repoRoot    func() string
	now         func() time.Time
	retention   func() int
}

func defaultProposeDeps() proposeDeps {
	return proposeDeps{
		eventLogDir: func() (string, error) {
			if err := config.LoadError(); err != nil {
				return "", err
			}
			if config.Get().Config.SkipEventLogging {
				return "", errors.New("event logging is off")
			}
			return config.Get().EventLogDir(), nil
		},
		repoRoot:  pmgsandbox.RepoRootOfCwd,
		now:       time.Now,
		retention: func() int { return config.Get().Config.EventLogRetentionDays },
	}
}

func newProfileProposeCommand(factory registryFactory, deps proposeDeps) *cobra.Command {
	opts := &profileProposeOptions{}

	cmd := &cobra.Command{
		Use:   "propose [--run <id> | --last | --since <window>] [--new <name|path> | --into <path>] [--dry-run]",
		Short: "Propose network rules from the destinations a run reached",
		Long: "Read the destinations the proxy saw in a run. Propose one allow rule per host and\n" +
			"port, plus a catch-all deny, as the network block of a sandbox profile.\n\n" +
			"The source is the event log. A run under audit with no profile records every\n" +
			"destination. --run picks one run by id. --last picks the newest run of this\n" +
			"repository. --since picks every run of this repository in a window (the default).\n\n" +
			"Without --new or --into the command prints the destinations and the proposed block.\n" +
			"--new writes a profile that inherits the built-in profile of the package manager that\n" +
			"ran. --into adds the rules to an existing profile and keeps its other blocks. --dry-run\n" +
			"shows what --new or --into would write. A proposal adds rules. It does not remove rules.",
		Example: "  pmg sandbox profile propose --run 3f2a9c1d7e4b\n" +
			"  pmg sandbox profile propose --last --new ci-network\n" +
			"  pmg sandbox profile propose --since 30d --into .pmg/profiles/ci.yml --dry-run",
		Args:          cobra.NoArgs,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := runProfilePropose(cmd.OutOrStdout(), opts, factory, deps); err != nil {
				return sandboxErrorExit(cmd, err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.section, "section", proposeSectionNetwork, "Profile section to propose. Only network is supported")
	cmd.Flags().StringVar(&opts.run, "run", "", "Use one run, by the id in the run report")
	cmd.Flags().BoolVar(&opts.last, "last", false, "Use the newest run of this repository")
	cmd.Flags().StringVar(&opts.since, "since", "", "Use every run of this repository in a window, such as 30d or 12h (default "+proposeDefaultWindow+")")
	cmd.Flags().StringVar(&opts.newRef, "new", "", "Write a new profile. Give a name for the user profile directory, or a file path")
	cmd.Flags().StringVar(&opts.into, "into", "", "Add the rules to this profile file")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "Show what --new or --into would write")
	cmd.Flags().BoolVar(&opts.json, "json", false, "Print the destinations and the proposal as JSON")
	return cmd
}

func runProfilePropose(out io.Writer, opts *profileProposeOptions, factory registryFactory, deps proposeDeps) error {
	if err := validateProposeOptions(opts); err != nil {
		return err
	}

	records, err := loadRecords(opts, deps)
	if err != nil {
		return err
	}

	registry, err := factory()
	if err != nil {
		return registryInitError(err)
	}

	target, err := resolveProposeTarget(opts, records, registry)
	if err != nil {
		return err
	}

	result, err := propose.Network(propose.Input{
		Destinations: netobserve.Merge(records),
		Parent:       target.parent,
		Existing:     target.existing,
	})
	if err != nil {
		return wrapUseful(err, errcodes.InvalidArgument, "Fix the rule the message names, then retry.")
	}

	rendered, err := target.render(result.Network)
	if err != nil {
		return wrapUseful(err, errcodes.InvalidArgument, "Fix the profile file, or pass --new to write a fresh one.")
	}

	write := target.path != "" && !opts.dryRun
	if opts.json {
		return writeProposeJSON(out, records, result, target, rendered, write, registry)
	}

	if err := printProposeTable(out, result.Rows); err != nil {
		return err
	}
	if err := printProposal(out, target, rendered, result); err != nil {
		return err
	}
	switch {
	case write:
		if err := target.write(rendered, registry); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "\nWrote %s\n", target.path)
	case opts.dryRun:
		_, err = fmt.Fprintln(out, "\nDry run. No file was written.")
	}
	return err
}

func validateProposeOptions(opts *profileProposeOptions) error {
	if opts.section != proposeSectionNetwork {
		return invalidArgumentError(
			fmt.Sprintf("section %q is not supported", opts.section),
			"Only the network section comes from observed destinations. For the other sections, run `pmg sandbox allow --last --all`.",
		)
	}
	sources := 0
	for _, set := range []bool{opts.run != "", opts.last, opts.since != ""} {
		if set {
			sources++
		}
	}
	if sources > 1 {
		return invalidArgumentError("--run, --last and --since are mutually exclusive", "Use only one of them.")
	}
	if opts.newRef != "" && opts.into != "" {
		return invalidArgumentError("--new and --into are mutually exclusive", "Use only one of them.")
	}
	return nil
}

// loadRecords reads the runs the options select. --run and --last read
// the whole log, because the run the user names or the newest run can be
// older than the default window.
func loadRecords(opts *profileProposeOptions, deps proposeDeps) ([]netobserve.Record, error) {
	dir, err := deps.eventLogDir()
	if err != nil {
		return nil, wrapUseful(err, errcodes.InvalidArgument,
			"The command reads the event log. Set skip_event_logging to false, run the package manager command again, then propose.")
	}

	window := proposeDefaultWindow
	if opts.since != "" {
		window = opts.since
	}
	since, err := netobserve.ParseWindow(window, deps.now())
	if err != nil {
		return nil, invalidArgumentError(err.Error(), "Use a number of days such as 30d, or a duration such as 12h.")
	}
	if opts.run != "" || opts.last {
		since = time.Time{}
	}

	records, err := netobserve.Read(dir, since)
	if err != nil {
		return nil, wrapUseful(err, errcodes.Unknown, "Check the event log directory "+dir+".")
	}

	selected := netobserve.Select(records, netobserve.Selector{RunID: opts.run, RepoRoot: deps.repoRoot(), Last: opts.last})
	if len(selected) == 0 {
		return nil, noRunError(opts, window, deps.retention())
	}
	return selected, nil
}

func noRunError(opts *profileProposeOptions, window string, retentionDays int) error {
	keep := fmt.Sprintf("The event log keeps %d day(s).", retentionDays)
	switch {
	case opts.run != "":
		return notFoundError(
			fmt.Sprintf("no run %s in the event log", opts.run),
			keep+" Run the package manager command again and use the run id from its report.",
		)
	case opts.last:
		return notFoundError(
			"no run of this repository in the event log",
			keep+" Run a package manager command through pmg from this repository, then retry.",
		)
	default:
		return notFoundError(
			fmt.Sprintf("no run of this repository in the last %s", window),
			keep+" Run a package manager command through pmg from this repository, then retry.",
		)
	}
}

// proposeTarget is the file the proposal goes to. A proposal with no
// target prints the network block only.
type proposeTarget struct {
	path     string
	isNew    bool
	mode     os.FileMode
	original []byte
	parent   *pmgsandbox.SandboxPolicy
	existing *pmgsandbox.NetworkPolicy

	// For a new profile.
	name            string
	packageManagers []string
	runIDs          []string
	now             time.Time
}

func resolveProposeTarget(opts *profileProposeOptions, records []netobserve.Record, registry pmgsandbox.ProfileRegistry) (*proposeTarget, error) {
	target := &proposeTarget{now: time.Now()}
	for _, record := range records {
		target.runIDs = append(target.runIDs, record.RunID)
	}

	switch {
	case opts.into != "":
		return resolveIntoTarget(target, opts.into, registry)
	case opts.newRef != "":
		return resolveNewTarget(target, opts.newRef, records, registry)
	}

	// No target. The proposal still inherits the run's built-in, so the
	// printed block does not repeat the registry hosts.
	parent, err := proposeParent(records, registry)
	if err != nil {
		return nil, err
	}
	target.parent = parent
	return target, nil
}

// resolveIntoTarget reads the profile's own network block from its file
// and its parent from the registry's resolution of the file, so a parent
// named by a path relative to the file resolves as the loader resolves it.
func resolveIntoTarget(target *proposeTarget, path string, registry pmgsandbox.ProfileRegistry) (*proposeTarget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, wrapUseful(fmt.Errorf("read %s: %w", path, err), ioErrorCode(err, errcodes.NotFound),
			"Pass --into an existing profile file, or --new to write one.")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, wrapUseful(fmt.Errorf("stat %s: %w", path, err), ioErrorCode(err, errcodes.NotFound),
			"Pass --into an existing profile file, or --new to write one.")
	}
	var own pmgsandbox.SandboxPolicy
	if err := yaml.Unmarshal(data, &own); err != nil {
		return nil, wrapUseful(fmt.Errorf("parse %s: %w", path, err), errcodes.InvalidArgument,
			"Fix the YAML, or run `pmg sandbox profile lint "+path+"`.")
	}
	resolved, err := registry.LoadCustomProfile(path)
	if err != nil {
		return nil, profileLoadError(err)
	}

	target.path = path
	target.mode = info.Mode().Perm()
	target.original = data
	target.existing = &own.Network
	if chain := resolved.Lineage; len(chain) > 1 {
		parent, err := registry.GetProfile(chain[len(chain)-2])
		if err != nil {
			return nil, profileLoadError(err)
		}
		target.parent = parent
	}
	return target, nil
}

func resolveNewTarget(target *proposeTarget, ref string, records []netobserve.Record, registry pmgsandbox.ProfileRegistry) (*proposeTarget, error) {
	target.isNew = true
	target.mode = 0o644
	var taken []string
	if executor.IsProfilePath(ref) {
		target.path = ref
		target.name = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(ref), ".yml"), ".yaml")
		taken = []string{ref}
	} else {
		if !profileNameRe.MatchString(ref) {
			return nil, invalidArgumentError(fmt.Sprintf("invalid profile name %q", ref), "Use a single path-safe name matching "+profileNameRe.String()+", or a path ending in .yml.")
		}
		userDir := registry.UserProfileDir()
		if userDir == "" {
			return nil, invalidArgumentError("user profile directory is not configured", "Pass --new with a path instead.")
		}
		target.path = filepath.Join(userDir, ref+".yml")
		target.name = ref
		// The registry reads both extensions and prefers .yml, so a new
		// .yml file would shadow a .yaml profile of the same name.
		taken = []string{target.path, filepath.Join(userDir, ref+".yaml")}
	}
	for _, path := range taken {
		if _, err := os.Stat(path); err == nil {
			return nil, invalidArgumentError(fmt.Sprintf("profile already exists at %s", path), "Use --into "+path+" to add the rules to it.")
		}
	}

	parent, err := proposeParent(records, registry)
	if err != nil {
		return nil, err
	}
	target.parent = parent
	target.packageManagers = parent.PackageManagers
	if pm := runPackageManager(records); pm != "" {
		target.packageManagers = []string{pm}
	}
	return target, nil
}

// proposeParent is the built-in the proposal builds on: the built-in named
// after the package manager that ran, or exec for a daemon run.
func proposeParent(records []netobserve.Record, registry pmgsandbox.ProfileRegistry) (*pmgsandbox.SandboxPolicy, error) {
	name := proposeDaemonParent
	if pm := runPackageManager(records); pm != "" {
		if _, ok := registry.BuiltinProfileYAML(pm); ok {
			name = pm
		}
	}
	parent, err := registry.GetProfile(name)
	if err != nil {
		return nil, profileLoadError(err)
	}
	return parent, nil
}

// runPackageManager is the one package manager every selected run used,
// or empty when the runs disagree or a daemon ran.
func runPackageManager(records []netobserve.Record) string {
	pm := ""
	for _, record := range records {
		if record.PackageManager == "" || (pm != "" && record.PackageManager != pm) {
			return ""
		}
		pm = record.PackageManager
	}
	return pm
}

// render is the file content the proposal writes. With no target it is the
// network block alone.
func (t *proposeTarget) render(network pmgsandbox.NetworkPolicy) ([]byte, error) {
	switch {
	case t.path == "":
		return propose.RenderBlock(network), nil
	case t.isNew:
		return t.renderNew(network), nil
	default:
		return propose.SetBlock(t.original, network)
	}
}

func (t *proposeTarget) renderNew(network pmgsandbox.NetworkPolicy) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Proposed by `pmg sandbox profile propose` on %s from run %s.\n", t.now.Format("2006-01-02"), strings.Join(t.runIDs, ", "))
	b.WriteString("# Review every rule. One run does not reach every destination the job needs.\n")
	fmt.Fprintf(&b, "name: %s\n", yamlString(t.name))
	b.WriteString("description: network baseline from observed destinations\n")
	fmt.Fprintf(&b, "inherits: %s\n", yamlString(t.parent.Name))
	b.WriteString("package_managers:\n")
	for _, pm := range t.packageManagers {
		fmt.Fprintf(&b, "  - %s\n", yamlString(pm))
	}
	b.WriteString("\n")
	b.Write(propose.RenderBlock(network))
	return b.Bytes()
}

// write loads the rendered profile through the registry before it replaces
// the target, so a broken proposal cannot replace a profile that loads.
// The check runs on a temporary file next to the target.
func (t *proposeTarget) write(rendered []byte, registry pmgsandbox.ProfileRegistry) error {
	dir := filepath.Dir(t.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return wrapUseful(fmt.Errorf("create %s: %w", dir, err), ioErrorCode(err, errcodes.PermissionDenied),
			"Check the permissions of the target directory.")
	}
	tmp, err := os.CreateTemp(dir, ".propose-*.yml")
	if err != nil {
		return wrapUseful(fmt.Errorf("write %s: %w", t.path, err), ioErrorCode(err, errcodes.PermissionDenied),
			"Check the permissions of the target directory.")
	}
	defer func() {
		if err := os.Remove(tmp.Name()); err != nil && !os.IsNotExist(err) {
			log.Warnf("remove %s: %v", tmp.Name(), err)
		}
	}()
	if _, err := tmp.Write(rendered); err != nil {
		return wrapUseful(fmt.Errorf("write %s: %w", tmp.Name(), err), ioErrorCode(err, errcodes.PermissionDenied), "Check the free space and the permissions of the target directory.")
	}
	if err := tmp.Close(); err != nil {
		return wrapUseful(fmt.Errorf("write %s: %w", tmp.Name(), err), ioErrorCode(err, errcodes.PermissionDenied), "Check the free space and the permissions of the target directory.")
	}
	if _, err := registry.LoadCustomProfile(tmp.Name()); err != nil {
		return profileLoadError(err)
	}
	if err := os.Chmod(tmp.Name(), t.mode); err != nil {
		return wrapUseful(fmt.Errorf("write %s: %w", t.path, err), ioErrorCode(err, errcodes.PermissionDenied), "Check the permissions of the target directory.")
	}
	if err := os.Rename(tmp.Name(), t.path); err != nil {
		return wrapUseful(fmt.Errorf("write %s: %w", t.path, err), ioErrorCode(err, errcodes.PermissionDenied), "Check the permissions of the target path.")
	}
	return nil
}

func printProposeTable(out io.Writer, rows []propose.Row) error {
	if _, err := fmt.Fprintf(out, "Observed %d destination(s)\n\n", len(rows)); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "DESTINATION\tCLIENT\tCOUNT\tFIRST SEEN\tLAST SEEN\tDECISION\tPROPOSAL"); err != nil {
		return err
	}
	for _, row := range rows {
		proposal := string(row.Verdict)
		if row.Rule != "" {
			proposal += " " + row.Rule
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			row.Address(), row.Client, row.Count,
			row.FirstSeen.Local().Format("2006-01-02 15:04"), row.LastSeen.Local().Format("2006-01-02 15:04"),
			decisionLabel(row.Destination), proposal); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func decisionLabel(d netpolicy.Destination) string {
	switch {
	case d.Allowed:
		return "allowed"
	case d.Enforced:
		return "denied by " + d.Rule
	default:
		return "would deny by " + d.Rule
	}
}

func printProposal(out io.Writer, target *proposeTarget, rendered []byte, result propose.Result) error {
	if _, err := fmt.Fprintf(out, "\nProposal: %d new allow rule(s)\n\n", len(result.Added)); err != nil {
		return err
	}
	switch {
	case target.path == "":
		if _, err := out.Write(rendered); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "\nTo write it, use --new <name|path> or --into <path>.")
		return err
	case target.isNew:
		if _, err := fmt.Fprintf(out, "New profile %s:\n\n", target.path); err != nil {
			return err
		}
		_, err := out.Write(rendered)
		return err
	default:
		diff, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
			A:        difflib.SplitLines(string(target.original)),
			B:        difflib.SplitLines(string(rendered)),
			FromFile: target.path,
			ToFile:   target.path + " (proposed)",
			Context:  3,
		})
		if err != nil {
			return err
		}
		if diff == "" {
			diff = "No change. The profile already allows every destination.\n"
		}
		_, err = io.WriteString(out, diff)
		return err
	}
}

type proposeJSON struct {
	RunIDs       []string                 `json:"run_ids"`
	Destinations []propose.Row            `json:"destinations"`
	Network      pmgsandbox.NetworkPolicy `json:"network"`
	Added        []string                 `json:"added"`
	Target       string                   `json:"target,omitempty"`
	Content      string                   `json:"content"`
	Written      bool                     `json:"written"`
}

func writeProposeJSON(out io.Writer, records []netobserve.Record, result propose.Result, target *proposeTarget, rendered []byte, write bool, registry pmgsandbox.ProfileRegistry) error {
	if write {
		if err := target.write(rendered, registry); err != nil {
			return err
		}
	}
	report := proposeJSON{
		RunIDs:       make([]string, 0, len(records)),
		Destinations: result.Rows,
		Network:      result.Network,
		Added:        result.Added,
		Target:       target.path,
		Content:      string(rendered),
		Written:      write,
	}
	for _, record := range records {
		report.RunIDs = append(report.RunIDs, record.RunID)
	}
	if report.Added == nil {
		report.Added = []string{}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
