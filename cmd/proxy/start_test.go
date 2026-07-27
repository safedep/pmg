package proxy

import (
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDaemonArgsPrependsChangedConfigFlags(t *testing.T) {
	root := &cobra.Command{Use: "pmg"}
	config.ApplyCobraFlags(root)

	var got []string
	start := &cobra.Command{
		Use: "start",
		Run: func(cmd *cobra.Command, _ []string) {
			got = daemonArgs(cmd, "/tmp/proxy-state.json", "127.0.0.1", 9000, false)
		},
	}
	proxyCmd := &cobra.Command{Use: "proxy"}
	proxyCmd.AddCommand(start)
	root.AddCommand(proxyCmd)
	root.SetArgs([]string{
		"--paranoid",
		"--skip-dependency-cooldown",
		"proxy", "start",
	})

	require.NoError(t, root.Execute())
	assert.Equal(t, []string{
		"--paranoid=true",
		"--skip-dependency-cooldown=true",
		"proxy", "start", "--foreground-internal",
		"--state", "/tmp/proxy-state.json",
		"--host", "127.0.0.1",
		"--port", "9000",
		"--transparent=false",
	}, got)
}

// The daemon re-execs itself, so a transparent value supplied by flag must be
// carried across explicitly. The child's own config load cannot see it.
func TestDaemonArgsCarriesTransparentToChild(t *testing.T) {
	root := &cobra.Command{Use: "pmg"}
	config.ApplyCobraFlags(root)

	var got []string
	start := &cobra.Command{
		Use: "start",
		Run: func(cmd *cobra.Command, _ []string) {
			got = daemonArgs(cmd, "/tmp/proxy-state.json", "127.0.0.1", 9000, true)
		},
	}
	proxyCmd := &cobra.Command{Use: "proxy"}
	proxyCmd.AddCommand(start)
	root.AddCommand(proxyCmd)
	root.SetArgs([]string{"proxy", "start"})

	require.NoError(t, root.Execute())
	assert.Contains(t, got, "--transparent=true")
}
