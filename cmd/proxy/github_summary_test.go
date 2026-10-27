package proxy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunGitHubSummary(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "stop.json")
	require.NoError(t, os.WriteFile(report, []byte(`{"stopped":true,"state_verified":true,"blocked_count":2,"violation":"2 package(s) were blocked by the proxy"}`), 0o644))
	proposal := filepath.Join(dir, "proposal.json")
	require.NoError(t, os.WriteFile(proposal, []byte(`{"added":["a.example:443"],"new":true,"content":"name: network\n"}`), 0o644))

	tests := []struct {
		name        string
		summaryPath string
		opts        githubSummaryOptions
		wantOut     []string
		wantSummary []string
	}{
		{
			name:        "summary file and proposal",
			summaryPath: filepath.Join(dir, "summary.md"),
			opts:        githubSummaryOptions{report: report, proposal: proposal, profile: ".pmg/network.yml", failOnViolation: true},
			wantOut:     []string{"::error title=PMG::PMG blocked 2 package(s)", "::notice title=PMG::PMG proposes 1 network rule(s)"},
			wantSummary: []string{"# existing\n## PMG", "**Failed.** 2 package(s) were blocked by the proxy.", "name: network"},
		},
		{
			name:    "no summary file writes the summary to out",
			opts:    githubSummaryOptions{report: report},
			wantOut: []string{"## PMG", "**Passed with violations.**", "::warning title=PMG::PMG blocked 2 package(s)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.summaryPath != "" {
				require.NoError(t, os.WriteFile(tt.summaryPath, []byte("# existing\n"), 0o644))
			}
			var out bytes.Buffer
			require.NoError(t, runGitHubSummary(&out, &tt.opts, tt.summaryPath))
			for _, want := range tt.wantOut {
				assert.Contains(t, out.String(), want)
			}
			if tt.summaryPath == "" {
				return
			}
			assert.NotContains(t, out.String(), "## PMG")
			summary, err := os.ReadFile(tt.summaryPath)
			require.NoError(t, err)
			for _, want := range tt.wantSummary {
				assert.Contains(t, string(summary), want)
			}
		})
	}
}

func TestRunGitHubSummaryErrors(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("{"), 0o644))
	tests := []struct {
		name string
		opts githubSummaryOptions
	}{
		{"no report", githubSummaryOptions{}},
		{"missing report", githubSummaryOptions{report: filepath.Join(t.TempDir(), "none.json")}},
		{"broken report", githubSummaryOptions{report: bad}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Error(t, runGitHubSummary(&bytes.Buffer{}, &tt.opts, ""))
		})
	}
}
