package proxyserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	pmgproxy "github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAndReadState(t *testing.T) {
	dir := t.TempDir()
	path := stateFilePath(dir)

	s := State{PID: 12345, Addr: "127.0.0.1:9999", CACertPath: "/tmp/ca.pem"}
	require.NoError(t, writeState(path, s))

	got, err := readState(path)
	require.NoError(t, err)
	assert.Equal(t, s.PID, got.PID)
	assert.Equal(t, s.Addr, got.Addr)
	assert.Equal(t, s.CACertPath, got.CACertPath)
}

// TestBlockedPackageJSON fixes the JSON form of a stored block. A daemon and
// a `pmg proxy stop` of another version read the same state file.
func TestBlockedPackageJSON(t *testing.T) {
	blocked := []BlockedPackage{
		{Reason: pmgproxy.BlockReasonMalware, Context: &pmgproxy.BlockContext{
			Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, PackageName: "safedep-test-pkg", PackageVersion: "0.1.3",
		}},
		{Reason: pmgproxy.BlockReasonPolicyRule, Context: &pmgproxy.BlockContext{
			Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, PackageName: "ms", PackageVersion: "2.1.2",
			PolicyRule: &pmgproxy.PolicyRuleBlock{RuleID: "r_gw6r5edbmx", Cloud: true, Revision: 125},
		}},
		{Reason: pmgproxy.BlockReasonDependencyCooldown, Context: &pmgproxy.BlockContext{
			PackageName: "left-pad", PackageVersion: "1.3.1",
		}},
	}

	data, err := json.Marshal(blocked)
	require.NoError(t, err)
	assert.JSONEq(t, `[
		{"reason":"malware","context":{"ecosystem":2,"package_name":"safedep-test-pkg","package_version":"0.1.3"}},
		{"reason":"policy_rule","context":{"ecosystem":2,"package_name":"ms","package_version":"2.1.2",
			"policy_rule":{"rule_id":"r_gw6r5edbmx","cloud":true,"revision":125}}},
		{"reason":"dependency_cooldown","context":{"package_name":"left-pad","package_version":"1.3.1"}}
	]`, string(data))

	var got []BlockedPackage
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, blocked, got)
}

func TestBlockReasonJSONUnknownReason(t *testing.T) {
	var got BlockedPackage
	require.NoError(t, json.Unmarshal([]byte(`{"reason":"reason_of_a_newer_daemon","context":{"package_name":"ms"}}`), &got))
	assert.Equal(t, pmgproxy.BlockReasonNone, got.Reason, "a newer reason does not make the state file unreadable")
	assert.Equal(t, "ms", got.Context.PackageName)

	data, err := json.Marshal(BlockedPackage{Reason: pmgproxy.BlockReason(99)})
	require.NoError(t, err, "a reason with no name must not fail the final state write")
	assert.JSONEq(t, `{"reason":"none","context":null}`, string(data))
}

func TestWriteStateKeepsTheCountWithAnUnnamedReason(t *testing.T) {
	path := stateFilePath(t.TempDir())
	require.NoError(t, writeState(path, State{PID: 1, BlockedCount: 1, Blocked: []BlockedPackage{
		{Reason: pmgproxy.BlockReason(99), Context: &pmgproxy.BlockContext{PackageName: "ms"}},
	}}))

	got, err := readState(path)
	require.NoError(t, err)
	assert.Equal(t, 1, got.BlockedCount)
}

func TestBlockLog(t *testing.T) {
	ms := &pmgproxy.BlockContext{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, PackageName: "ms", PackageVersion: "2.1.2"}
	pypiMs := &pmgproxy.BlockContext{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI, PackageName: "ms", PackageVersion: "2.1.2"}

	l := &blockLog{seen: map[string]bool{}}
	l.Record(pmgproxy.BlockReasonPolicyRule, ms)
	l.Record(pmgproxy.BlockReasonPolicyRule, ms)
	l.Record(pmgproxy.BlockReasonDependencyCooldown, ms)
	l.Record(pmgproxy.BlockReasonPolicyRule, pypiMs)
	l.Record(pmgproxy.BlockReasonNone, nil)

	assert.Equal(t, []BlockedPackage{
		{Reason: pmgproxy.BlockReasonPolicyRule, Context: ms},
		{Reason: pmgproxy.BlockReasonDependencyCooldown, Context: ms},
		{Reason: pmgproxy.BlockReasonPolicyRule, Context: pypiMs},
	}, l.List())
}

func TestWriteStateCreatesMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "proxy-state.json")
	require.NoError(t, writeState(path, State{PID: 1, Addr: "127.0.0.1:1"}))

	got, err := readState(path)
	require.NoError(t, err)
	assert.Equal(t, 1, got.PID)
}

func TestReadStateMissingFile(t *testing.T) {
	_, err := readState(filepath.Join(t.TempDir(), "nonexistent.json"))
	assert.Error(t, err)
}

func TestRemoveState(t *testing.T) {
	dir := t.TempDir()
	path := stateFilePath(dir)

	require.NoError(t, writeState(path, State{PID: 1, Addr: "127.0.0.1:1"}))
	require.NoError(t, removeState(path))

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestIsRunningDeadPID(t *testing.T) {
	s := State{PID: 999999999}
	assert.False(t, s.IsRunning())
}

func TestStateFilePath(t *testing.T) {
	assert.Equal(t, filepath.Join("/some/dir", "proxy-state.json"), stateFilePath("/some/dir"))
}

func TestResolveStatePath(t *testing.T) {
	t.Run("flag override wins", func(t *testing.T) {
		assert.Equal(t, "/custom/proxy.json", ResolveStatePath("/custom/proxy.json", "/cache"))
	})

	t.Run("defaults to cacheDir", func(t *testing.T) {
		assert.Equal(t, filepath.Join("/cache", "proxy-state.json"), ResolveStatePath("", "/cache"))
	})
}

func TestStateNotices(t *testing.T) {
	tests := []struct {
		name  string
		state State
		want  []string
	}{
		{name: "no notices", state: State{}, want: nil},
		{name: "daemon notices only", state: State{Warnings: []string{"go"}}, want: []string{"go"}},
		{
			name:  "daemon notices come before enforcement notices",
			state: State{Warnings: []string{"go"}, Enforce: &EnforceState{Warnings: []string{"docker"}}},
			want:  []string{"go", "docker"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.state.Notices())
		})
	}
}

func TestGetStatusReportsEveryNotice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, writeState(path, State{
		PID:      os.Getpid(),
		Warnings: []string{"go"},
		Enforce:  &EnforceState{Warnings: []string{"docker"}},
	}))

	assert.Equal(t, []string{"go", "docker"}, GetStatus(path).Warnings)
}
