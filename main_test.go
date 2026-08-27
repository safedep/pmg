package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestShouldSuppressBackgroundSync(t *testing.T) {
	tests := []struct {
		name string
		path []string
		want bool
	}{
		{name: "proxy", path: []string{"proxy"}, want: true},
		{name: "proxy subcommand", path: []string{"proxy", "start"}, want: true},
		{name: "setup remove", path: []string{"setup", "remove"}, want: true},
		{name: "top-level remove", path: []string{"remove"}, want: true},
		{name: "setup install", path: []string{"setup", "install"}, want: false},
		{name: "package manager", path: []string{"npm"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, shouldSuppressBackgroundSync(testCommand(tt.path...)))
		})
	}
}

func testCommand(path ...string) *cobra.Command {
	root := &cobra.Command{Use: "pmg"}
	current := root
	for _, name := range path {
		child := &cobra.Command{Use: name}
		current.AddCommand(child)
		current = child
	}
	return current
}
