package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	acc "github.com/safedep/pmg/test/acceptance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatusesFromJUnit(t *testing.T) {
	xmlIn := `<testsuites><testsuite>
	  <testcase name="TestAcceptance/npm/guard/malware-block"></testcase>
	  <testcase name="TestAcceptance/npm/install/clean-allow"><failure message="boom">boom</failure></testcase>
	  <testcase name="TestAcceptance/cloud/analyzer/authenticated-query-blocks-malware"><skipped message="no cloud credentials"></skipped></testcase>
	  <testcase name="TestAcceptance/npm/guard"></testcase>
	</testsuite></testsuites>`

	got, err := statusesFromJUnit([]byte(xmlIn))
	require.NoError(t, err)
	assert.Equal(t, StatusPass, got["npm/guard/malware-block"])
	assert.Equal(t, StatusFail, got["npm/install/clean-allow"])
	assert.Equal(t, StatusSkip, got["cloud/analyzer/authenticated-query-blocks-malware"])
	assert.Equal(t, StatusPass, got["npm/guard"]) // parent aggregate; ignored later (not a catalog id)
}

func TestStatusesFromJUnitIgnoresNonAcceptance(t *testing.T) {
	xmlIn := `<testsuites><testsuite>
	  <testcase name="TestCatalogIntegrity"></testcase>
	  <testcase name="TestAcceptance/setup/install/shims-created"></testcase>
	</testsuite></testsuites>`

	got, err := statusesFromJUnit([]byte(xmlIn))
	require.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, StatusPass, got["setup/install/shims-created"])
}

func TestSummarize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- id: npm/guard/malware-block
  surface: npm
  tier: P0
  guarantee: x
- id: pnpm/guard/malware-block
  surface: pnpm
  tier: P0
  guarantee: y
`), 0o600))
	cat, err := acc.LoadCatalog(path)
	require.NoError(t, err)

	sum := summarize(cat, map[string]Status{"npm/guard/malware-block": StatusPass})
	assert.Equal(t, 1, sum.Counts[StatusPass])
	assert.Equal(t, 1, sum.Counts[StatusGap]) // pnpm has no result
	assert.Len(t, sum.Rows, 2)
}

func TestRenderShowsFailureSnippetAndCoverage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- id: npm/guard/malware-block
  surface: npm
  tier: P0
  guarantee: a malware verdict is never installed
- id: npm/install/clean-allow
  surface: npm
  tier: P1
  guarantee: a clean package installs
`), 0o600))
	cat, err := acc.LoadCatalog(path)
	require.NoError(t, err)

	results := map[string]result{
		"npm/guard/malware-block": {status: StatusPass},
		"npm/install/clean-allow": {status: StatusFail, message: "unexpected command success"},
	}
	statuses := map[string]Status{}
	for id, r := range results {
		statuses[id] = r.status
	}

	var b strings.Builder
	render(&b, summarize(cat, statuses), results)
	out := b.String()

	assert.Contains(t, out, "npm/guard/malware-block")
	assert.Contains(t, out, "unexpected command success")
	assert.Contains(t, out, "1/1") // P0 coverage: 1 pass of 1
	assert.Contains(t, out, "## npm")
}
