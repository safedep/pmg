package ui

import (
	"io"
	"os"
	"strings"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func malwareBlockedData() *ReportData {
	data := NewReportData()
	data.TotalAnalyzed = 1
	data.BlockedCount = 1
	data.Outcome = OutcomeBlocked
	data.BlockedPackages = []*analyzer.PackageVersionAnalysisResult{
		{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{Name: "evil", Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
				Version: "1.0.0",
			},
			Summary: "verified malware",
		},
	}
	return data
}

func TestReportNormalMalwareCustomMessage(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	data := malwareBlockedData()
	data.BlockMessage = "Contact #security-help"

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Malicious package blocked")
	assert.Contains(t, out, "Contact #security-help")
}

func TestReportNormalNoCustomMessageWhenUnset(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	out := captureStdout(t, func() { Report(malwareBlockedData()) })
	assert.Contains(t, out, "Malicious package blocked")
	assert.NotContains(t, out, "Contact #security-help")
}

func TestReportNormalCooldownCustomMessage(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	data := NewReportData()
	data.TotalAnalyzed = 1
	data.BlockedCount = 1
	data.Outcome = OutcomeBlocked
	data.CooldownBlockedPackages = []models.CooldownBlock{{Name: "fresh", Version: "2.0.0", DaysAgo: 1, DaysLeft: 4, CooldownDays: 5}}
	data.BlockMessage = "Request an exemption at go/pmg-exceptions"

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Dependency cooldown")
	assert.Contains(t, out, "Request an exemption at go/pmg-exceptions")
}

func TestReportNormalBlocklistSection(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	data := NewReportData()
	data.TotalAnalyzed = 1
	data.BlockedCount = 1
	data.Outcome = OutcomeBlocked
	data.BlocklistBlockedPackages = []models.BlocklistBlock{{Name: "left-pad", Version: "1.3.0", Reason: "deprecated internally"}}
	data.BlockMessage = "Blocked by ACME security policy"

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Blocked by package policy")
	assert.Contains(t, out, "left-pad@1.3.0")
	assert.Contains(t, out, "deprecated internally")
	assert.Contains(t, out, "ℹ Blocked by ACME security policy")
	assert.NotContains(t, out, "\n\n\n", "no double blank lines in block output")
}

func TestReportSilentRendersBlocks(t *testing.T) {
	withVerbosity(t, VerbosityLevelSilent)

	data := malwareBlockedData()
	data.BlockMessage = "Contact #security-help"
	data.BlocklistBlockedPackages = []models.BlocklistBlock{{Name: "left-pad", Version: "1.3.0", Reason: "banned"}}

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Malicious package blocked")
	assert.Contains(t, out, "Contact #security-help")
	assert.Contains(t, out, "Blocked by package policy")
}

func TestReportSilentQuietOnSuccess(t *testing.T) {
	withVerbosity(t, VerbosityLevelSilent)

	data := NewReportData()
	data.TotalAnalyzed = 3

	out := captureStdout(t, func() { Report(data) })
	assert.Empty(t, out)
}

func TestReportSilentCooldownOnlyStaysQuiet(t *testing.T) {
	withVerbosity(t, VerbosityLevelSilent)

	data := NewReportData()
	data.TotalAnalyzed = 1
	data.BlockedCount = 1
	data.Outcome = OutcomeBlocked
	data.CooldownBlockedPackages = []models.CooldownBlock{{Name: "fresh", Version: "2.0.0"}}

	out := captureStdout(t, func() { Report(data) })
	assert.Empty(t, out)
}

func TestReportVerboseBlocklistDetails(t *testing.T) {
	withVerbosity(t, VerbosityLevelVerbose)

	data := NewReportData()
	data.TotalAnalyzed = 1
	data.BlockedCount = 1
	data.Outcome = OutcomeBlocked
	data.BlocklistBlockedPackages = []models.BlocklistBlock{{Name: "left-pad", Version: "1.3.0", Reason: "deprecated internally"}}

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Blocked by package policy")
	assert.Contains(t, out, "deprecated internally")
	assert.Contains(t, out, "Installation blocked")
}

func TestTermWidthFormatTextIndent(t *testing.T) {
	text := strings.Repeat("word ", 40)
	out := termWidthFormatTextIndent(text, 20, "    ")
	lines := strings.Split(out, "\n")
	require.Greater(t, len(lines), 1)
	for _, line := range lines[1:] {
		assert.True(t, strings.HasPrefix(line, "    "), "wrapped line must be indented: %q", line)
	}
}
