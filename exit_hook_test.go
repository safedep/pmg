package main

import (
	"context"
	"errors"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type unparsablePackageManager struct{}

func (unparsablePackageManager) Name() string { return "npm" }

func (unparsablePackageManager) ParseCommand([]string) (*packagemanager.ParsedCommand, error) {
	return nil, errors.New("unparsable command")
}

func (unparsablePackageManager) Ecosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_NPM
}

// The GitHub action probed `pmg cloud sync --help` with cloud on. The help
// started a background sync, and the sync lock it held failed the next
// `pmg cloud sync --require-policy`.
func TestExitHookStartsBackgroundSyncOnlyAfterAuditEvents(t *testing.T) {
	executeRoot := func(wantErr bool, args ...string) func(t *testing.T) {
		return func(t *testing.T) {
			cmd := newRootCommand()
			cmd.SetArgs(args)
			assert.Equal(t, wantErr, cmd.Execute() != nil)
		}
	}

	tests := []struct {
		name          string
		run           func(t *testing.T)
		exitThroughUI bool
		wantSpawn     int
	}{
		{name: "root help", run: executeRoot(false, "--help")},
		{name: "subcommand help", run: executeRoot(false, "cloud", "sync", "--help")},
		{name: "usage error", run: executeRoot(true, "cloud", "sync", "--no-such-flag")},
		{
			name: "package manager run",
			run: func(t *testing.T) {
				t.Cleanup(audit.UseSinksForTest())
				err := flows.RunProxy(context.Background(), unparsablePackageManager{}, []string{"install"})
				require.Error(t, err)
			},
			wantSpawn: 1,
		},
		{
			name: "blocked install exits through ui",
			run: func(t *testing.T) {
				t.Cleanup(audit.UseSinksForTest())
				audit.LogMalwareBlocked(&packagev1.PackageVersion{}, "malware", "", "", true, true)
			},
			exitThroughUI: true,
			wantSpawn:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PMG_CONFIG_DIR", t.TempDir())
			t.Setenv("PMG_STATE_DIR", t.TempDir())
			config.Reload()
			t.Cleanup(config.Reload)

			var spawns int
			t.Cleanup(audit.UseSpawnerForTest(func(string, ...string) error {
				spawns++
				return nil
			}))

			cfg := config.Get()
			cfg.Config.Cloud.Enabled = true
			cfg.Config.Cloud.AutoSync.Enabled = true
			cfg.Config.Cloud.AutoSync.MinInterval = time.Minute

			cleanup := installExitHook()
			t.Cleanup(func() { ui.SetExitHook(nil) })

			tt.run(t)
			if tt.exitThroughUI {
				ui.RunExitHook()
			} else {
				cleanup()
			}

			assert.Equal(t, tt.wantSpawn, spawns)
		})
	}
}
