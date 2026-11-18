package main

import (
	"testing"

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
		{name: "the daemon re-exec does not fetch", args: []string{"proxy", "start", "--foreground-internal"}},
		{name: "proxy stop does not fetch", args: []string{"proxy", "stop"}},
		{name: "cloud sync does not fetch at start", args: []string{"cloud", "sync"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := newTestRoot()
			cmd, args, err := root.Find(tt.args)
			require.NoError(t, err)
			require.NoError(t, cmd.ParseFlags(args))

			assert.Equal(t, tt.want, fetchesPolicyAtStart(cmd))
		})
	}
}

func newTestRoot() *cobra.Command {
	proxy := &cobra.Command{Use: "proxy"}
	start := &cobra.Command{Use: "start"}
	start.Flags().Bool("daemon", false, "")
	start.Flags().Bool("foreground-internal", false, "")
	proxy.AddCommand(start, &cobra.Command{Use: "stop"})

	cloud := &cobra.Command{Use: "cloud"}
	cloud.AddCommand(&cobra.Command{Use: "sync"})

	root := &cobra.Command{Use: "pmg"}
	root.AddCommand(proxy, cloud)
	return root
}
