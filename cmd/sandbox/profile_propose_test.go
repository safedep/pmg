package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/eventlog"
	"github.com/safedep/pmg/proxy/netpolicy"
	pmgsandbox "github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var proposeNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

type proposeFixture struct {
	logDir  string
	repo    string
	userDir string
}

// newProposeFixture resolves the repository the way the runs key their
// observations, so a temporary directory behind a symlink, as on macOS,
// compares equal.
func newProposeFixture(t *testing.T) proposeFixture {
	t.Helper()
	repo, err := pmgsandbox.ResolveRepoRoot(t.TempDir())
	require.NoError(t, err)
	return proposeFixture{logDir: t.TempDir(), repo: repo, userDir: t.TempDir()}
}

func (f proposeFixture) deps() proposeDeps {
	return proposeDeps{
		eventLogDir: func() (string, error) { return f.logDir, nil },
		repoRoot:    func() string { return f.repo },
		now:         func() time.Time { return proposeNow },
		retention:   func() int { return 7 },
	}
}

// logObservation appends one network_observation event the way the audit
// sink writes it.
func (f proposeFixture) logObservation(t *testing.T, at time.Time, obs netpolicy.Observation) {
	t.Helper()
	details := map[string]any{
		"run_id":          obs.RunID,
		"repo_root":       obs.RepoRoot,
		"package_manager": obs.PackageManager,
		"profile":         obs.Profile,
		"mode":            obs.Mode,
		"destinations":    obs.Destinations,
	}
	line, err := json.Marshal(eventlog.Event{Timestamp: at, EventType: string(audit.EventTypeNetworkObservation), Message: "test", Details: details})
	require.NoError(t, err)
	path := filepath.Join(f.logDir, at.Format("20060102")+"-pmg.log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	_, err = file.Write(append(line, '\n'))
	require.NoError(t, err)
}

func dest(host string, port uint16, count int) netpolicy.Destination {
	return netpolicy.Destination{Host: host, Port: port, Count: count, Allowed: true,
		FirstSeen: proposeNow.Add(-time.Hour), LastSeen: proposeNow.Add(-time.Minute)}
}

func (f proposeFixture) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newProfileProposeCommand(newTestRegistryFactory(t, f.userDir), f.deps())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestProfilePropose_DryRunPrintsTheTableAndWritesNothing(t *testing.T) {
	f := newProposeFixture(t)
	f.logObservation(t, proposeNow.Add(-2*time.Hour), netpolicy.Observation{RunID: "run1", RepoRoot: f.repo, PackageManager: "npm", Mode: "audit",
		Destinations: []netpolicy.Destination{dest("registry.npmjs.org", 443, 4), dest("cdn.example", 443, 1)}})

	out, err := f.run(t, "--last", "--new", "ci")
	require.NoError(t, err)
	assert.Contains(t, out, "Observed 2 destination(s)")
	assert.Contains(t, out, "parent allows registry.npmjs.org:443", "the npm built-in already names the registry")
	assert.Contains(t, out, "add cdn.example:443")
	assert.Contains(t, out, "Proposal: 1 new allow rule(s)")
	assert.Contains(t, out, "inherits: npm")
	assert.Contains(t, out, "    - cdn.example:443\n")
	assert.Contains(t, out, "deny_outbound: []", "the built-in already denies everything else")
	assert.NoFileExists(t, filepath.Join(f.userDir, "ci.yml"))
}

func TestProfilePropose_DaemonRunInheritsExecAndDeniesTheRest(t *testing.T) {
	f := newProposeFixture(t)
	f.logObservation(t, proposeNow.Add(-2*time.Hour), netpolicy.Observation{RunID: "run1", RepoRoot: f.repo, Mode: "audit",
		Destinations: []netpolicy.Destination{dest("registry.npmjs.org", 443, 4), dest("github.com", 443, 1)}})

	out, err := f.run(t, "--last", "--new", "ci")
	require.NoError(t, err)
	assert.Contains(t, out, "inherits: exec")
	assert.Contains(t, out, "add github.com:443")
	assert.Contains(t, out, "add registry.npmjs.org:443")
	assert.Contains(t, out, `- "*:*"`, "exec allows every host, so the proposal denies the rest itself")
}

func TestProfilePropose_WritesANewProfileThatLoads(t *testing.T) {
	f := newProposeFixture(t)
	f.logObservation(t, proposeNow.Add(-2*time.Hour), netpolicy.Observation{RunID: "run1", RepoRoot: f.repo, PackageManager: "npm", Mode: "audit",
		Destinations: []netpolicy.Destination{dest("registry.npmjs.org", 443, 4), dest("cdn.example", 443, 1)}})

	out, err := f.run(t, "--run", "run1", "--new", "ci", "--write")
	require.NoError(t, err)
	path := filepath.Join(f.userDir, "ci.yml")
	assert.Contains(t, out, "Wrote "+path)

	registry, err := newTestRegistryFactory(t, f.userDir)()
	require.NoError(t, err)
	policy, err := registry.GetProfile("ci")
	require.NoError(t, err)
	assert.Equal(t, []string{"npm"}, policy.PackageManagers)
	assert.Contains(t, policy.Network.AllowOutbound, "cdn.example:443")
	assert.Contains(t, policy.Network.AllowOutbound, "registry.npmjs.org:443", "inherited from the built-in")
	assert.Contains(t, policy.Network.DenyOutbound, "*:*", "inherited from the built-in")

	_, err = f.run(t, "--run", "run1", "--new", "ci", "--write")
	require.Error(t, err, "a second --new refuses to overwrite")
	assert.Contains(t, err.Error(), "already exists")
}

const proposeExistingProfile = `# The CI profile.
name: ci
description: the job's network
inherits: npm-restrictive
package_managers:
  - npm
filesystem:
  allow_write:
    - ${CWD}/dist/**
network:
  allow_outbound:
    - github.com:443
  deny_outbound:
    - pastebin.com:443
`

func TestProfilePropose_IntoAppendsAndKeepsTheOtherBlocks(t *testing.T) {
	f := newProposeFixture(t)
	target := filepath.Join(f.repo, "ci.yml")
	require.NoError(t, os.WriteFile(target, []byte(proposeExistingProfile), 0o644))
	f.logObservation(t, proposeNow.Add(-2*time.Hour), netpolicy.Observation{RunID: "run1", RepoRoot: f.repo, PackageManager: "npm", Mode: "enforce",
		Destinations: []netpolicy.Destination{
			dest("registry.npmjs.org", 443, 4),
			dest("github.com", 443, 1),
			dest("objects.githubusercontent.com", 443, 2),
			{Host: "pastebin.com", Port: 443, Count: 1, Allowed: false, Rule: "pastebin.com:443", Enforced: true, FirstSeen: proposeNow, LastSeen: proposeNow},
		}})

	out, err := f.run(t, "--last", "--into", target, "--write")
	require.NoError(t, err)
	assert.Contains(t, out, "+    - objects.githubusercontent.com:443")
	assert.Contains(t, out, "parent allows registry.npmjs.org:443")
	assert.Contains(t, out, "already allowed github.com:443")
	assert.Contains(t, out, "kept denied pastebin.com:443")

	written, err := os.ReadFile(target)
	require.NoError(t, err)
	want := strings.Replace(proposeExistingProfile,
		"    - github.com:443\n",
		"    - github.com:443\n    - objects.githubusercontent.com:443\n", 1)
	assert.Equal(t, want, string(written), "the other blocks and the comment stay as they were")

	out, err = f.run(t, "--last", "--into", target, "--write")
	require.NoError(t, err)
	assert.Contains(t, out, "No change")
	again, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, want, string(again), "a second proposal removes nothing")
}

func TestProfilePropose_SinceReadsOnlyThisRepository(t *testing.T) {
	f := newProposeFixture(t)
	f.logObservation(t, proposeNow.Add(-2*time.Hour), netpolicy.Observation{RunID: "mine", RepoRoot: f.repo, PackageManager: "npm",
		Destinations: []netpolicy.Destination{dest("mine.example", 443, 1)}})
	f.logObservation(t, proposeNow.Add(-time.Hour), netpolicy.Observation{RunID: "theirs", RepoRoot: t.TempDir(), PackageManager: "npm",
		Destinations: []netpolicy.Destination{dest("theirs.example", 443, 1)}})
	f.logObservation(t, proposeNow.Add(-40*24*time.Hour), netpolicy.Observation{RunID: "old", RepoRoot: f.repo, PackageManager: "npm",
		Destinations: []netpolicy.Destination{dest("old.example", 443, 1)}})

	out, err := f.run(t, "--since", "30d")
	require.NoError(t, err)
	assert.Contains(t, out, "mine.example:443")
	assert.NotContains(t, out, "theirs.example")
	assert.NotContains(t, out, "old.example")

	out, err = f.run(t, "--run", "theirs")
	require.NoError(t, err, "--run finds a run of another repository")
	assert.Contains(t, out, "theirs.example:443")
}

func TestProfilePropose_MergesTheRunsOfAWindow(t *testing.T) {
	f := newProposeFixture(t)
	f.logObservation(t, proposeNow.Add(-2*time.Hour), netpolicy.Observation{RunID: "a", RepoRoot: f.repo, PackageManager: "npm",
		Destinations: []netpolicy.Destination{dest("registry.npmjs.org", 443, 2)}})
	f.logObservation(t, proposeNow.Add(-time.Hour), netpolicy.Observation{RunID: "b", RepoRoot: f.repo, PackageManager: "npm",
		Destinations: []netpolicy.Destination{dest("registry.npmjs.org", 443, 3), dest("cdn.example", 443, 1)}})

	out, err := f.run(t, "--json")
	require.NoError(t, err)
	var report proposeJSON
	require.NoError(t, json.Unmarshal([]byte(out), &report))
	assert.Equal(t, []string{"a", "b"}, report.RunIDs)
	require.Len(t, report.Destinations, 2)
	assert.Equal(t, "cdn.example:443", report.Destinations[0].Address())
	assert.Equal(t, 5, report.Destinations[1].Count, "the counts of two runs add up")
	assert.Equal(t, []string{"cdn.example:443"}, report.Added)
	assert.False(t, report.Written)
}

func TestProfilePropose_Errors(t *testing.T) {
	f := newProposeFixture(t)
	f.logObservation(t, proposeNow.Add(-time.Hour), netpolicy.Observation{RunID: "run1", RepoRoot: f.repo, PackageManager: "npm",
		Destinations: []netpolicy.Destination{dest("github.com", 443, 1)}})

	tests := []struct {
		name string
		args []string
		code string
		want string
	}{
		{"unknown run", []string{"--run", "nope"}, errcodes.NotFound, "no run nope"},
		{"another section", []string{"--section", "filesystem"}, errcodes.InvalidArgument, "pmg sandbox allow --last --all"},
		{"write without target", []string{"--last", "--write"}, errcodes.InvalidArgument, "needs a target"},
		{"two targets", []string{"--last", "--new", "a", "--into", "b"}, errcodes.InvalidArgument, "mutually exclusive"},
		{"two sources", []string{"--last", "--run", "run1"}, errcodes.InvalidArgument, "mutually exclusive"},
		{"bad window", []string{"--since", "soon"}, errcodes.InvalidArgument, "invalid window"},
		{"bad name", []string{"--last", "--new", "bad..name"}, errcodes.InvalidArgument, "invalid profile name"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.run(t, tc.args...)
			require.Error(t, err)
			var useful usefulerror.UsefulError
			require.True(t, errors.As(err, &useful))
			assert.Equal(t, tc.code, useful.Code())
			assert.Contains(t, err.Error()+" "+useful.Help(), tc.want)
		})
	}
}

func TestProfilePropose_NoRunNamesTheWindowAndTheRetention(t *testing.T) {
	f := newProposeFixture(t)
	_, err := f.run(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no run of this repository in the last 30d")
}

func TestProfilePropose_EventLoggingOff(t *testing.T) {
	f := newProposeFixture(t)
	deps := f.deps()
	deps.eventLogDir = func() (string, error) { return "", errors.New("event logging is off") }
	cmd := newProfileProposeCommand(newTestRegistryFactory(t, f.userDir), deps)
	cmd.SetArgs([]string{"--last"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	require.Error(t, err)
	var useful usefulerror.UsefulError
	require.True(t, errors.As(err, &useful))
	assert.Contains(t, useful.Help(), "skip_event_logging")
}

func TestProfilePropose_NewPathWritesWhereItSaysAndLeavesNoTempFile(t *testing.T) {
	f := newProposeFixture(t)
	f.logObservation(t, proposeNow.Add(-time.Hour), netpolicy.Observation{RunID: "run1", RepoRoot: f.repo, PackageManager: "npm",
		Destinations: []netpolicy.Destination{dest("cdn.example", 443, 1)}})
	target := filepath.Join(f.repo, ".pmg", "profiles", "ci.yml")

	out, err := f.run(t, "--last", "--new", target, "--write")
	require.NoError(t, err)
	assert.Contains(t, out, "Wrote "+target)
	written, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(written), "name: ci\n")
	assert.Contains(t, string(written), "    - cdn.example:443\n")
	entries, err := os.ReadDir(filepath.Dir(target))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "the temporary file is gone")
}

func TestProfilePropose_LastReadsBeyondTheDefaultWindow(t *testing.T) {
	f := newProposeFixture(t)
	f.logObservation(t, proposeNow.Add(-45*24*time.Hour), netpolicy.Observation{RunID: "old", RepoRoot: f.repo, PackageManager: "npm",
		Destinations: []netpolicy.Destination{dest("old.example", 443, 1)}})

	out, err := f.run(t, "--last")
	require.NoError(t, err)
	assert.Contains(t, out, "old.example:443")
}

func TestProfilePropose_IntoASkeletonNetworkKey(t *testing.T) {
	f := newProposeFixture(t)
	target := filepath.Join(f.repo, "ci.yml")
	require.NoError(t, os.WriteFile(target, []byte("name: ci\ninherits: npm-restrictive\npackage_managers:\n  - npm\nnetwork:\n"), 0o644))
	f.logObservation(t, proposeNow.Add(-time.Hour), netpolicy.Observation{RunID: "run1", RepoRoot: f.repo, PackageManager: "npm",
		Destinations: []netpolicy.Destination{dest("cdn.example", 443, 1)}})

	_, err := f.run(t, "--last", "--into", target, "--write")
	require.NoError(t, err)
	written, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(written), "network:\n  allow_outbound:\n    - cdn.example:443\n")
}
