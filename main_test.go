package main

import (
	"testing"

	"github.com/safedep/pmg/cmd/cloud"
	proxyCmd "github.com/safedep/pmg/cmd/proxy"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchesPolicyAtStart(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "a foreground start fetches", args: []string{"proxy", "start"}, want: true},
		{name: "a daemon start fetches in the parent", args: []string{"proxy", "start", "--daemon"}, want: true},
		{name: "the daemon re-exec does not fetch", args: []string{"proxy", "start", "--" + proxyCmd.ForegroundInternalFlag}},
		{name: "proxy stop does not fetch", args: []string{"proxy", "stop"}},
		{name: "cloud sync does not fetch at start", args: []string{"cloud", "sync"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := &cobra.Command{Use: "pmg"}
			root.AddCommand(proxyCmd.NewProxyCommand(), cloud.NewCloudCommand())
			cmd, args, err := root.Find(tt.args)
			require.NoError(t, err)
			require.NoError(t, cmd.ParseFlags(args))

			assert.Equal(t, tt.want, fetchesPolicyAtStart(cmd))
		})
	}
}

func TestFetchesPolicyAtStartWithoutTheReexecFlag(t *testing.T) {
	root := &cobra.Command{Use: "pmg"}
	proxy := &cobra.Command{Use: "proxy"}
	proxy.AddCommand(&cobra.Command{Use: "start"})
	root.AddCommand(proxy)

	cmd, _, err := root.Find([]string{"proxy", "start"})
	require.NoError(t, err)
	assert.True(t, fetchesPolicyAtStart(cmd), "a start that cannot read the flag must not skip the policy check")
}
