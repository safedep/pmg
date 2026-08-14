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

func TestReportNormalMalwareAdvisoryMessage(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	data := malwareBlockedData()
	data.AdvisoryMessage = "Contact #security-help"

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Malicious package blocked")
	assert.Contains(t, out, "ℹ Contact #security-help")
	assert.NotContains(t, out, "\n\n\n", "no double blank lines in block output")
}

func TestReportNormalNoAdvisoryMessageWhenUnset(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	out := captureStdout(t, func() { Report(malwareBlockedData()) })
	assert.Contains(t, out, "Malicious package blocked")
	assert.NotContains(t, out, "Contact #security-help")
}

func TestReportNormalCooldownAdvisoryMessage(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	data := NewReportData()
	data.TotalAnalyzed = 1
	data.BlockedCount = 1
	data.Outcome = OutcomeBlocked
	data.CooldownBlockedPackages = []models.CooldownBlock{{Name: "fresh", Version: "2.0.0", DaysAgo: 1, DaysLeft: 4, CooldownDays: 5}}
	data.AdvisoryMessage = "Request an exemption at go/pmg-exceptions"

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Dependency cooldown")
	assert.Contains(t, out, "Request an exemption at go/pmg-exceptions")
}

func TestReportSilentRendersBlocks(t *testing.T) {
	withVerbosity(t, VerbosityLevelSilent)

	data := malwareBlockedData()
	data.AdvisoryMessage = "Contact #security-help"

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Malicious package blocked")
	assert.Contains(t, out, "Contact #security-help")
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

func TestReportVerboseAdvisoryMessage(t *testing.T) {
	withVerbosity(t, VerbosityLevelVerbose)

	data := malwareBlockedData()
	data.AdvisoryMessage = "Contact #security-help"

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Installation blocked")
	assert.Contains(t, out, "ℹ Contact #security-help")
}

func withheldData(outcome ExecutionOutcome) *ReportData {
	data := NewReportData()
	data.Outcome = outcome
	data.CooldownWithheldPackages = []models.CooldownWithheld{
		{Name: "@posthog/core", Versions: []models.CooldownWithheldVersion{{Version: "1.47.0", DaysLeft: 2}}},
	}
	return data
}

func TestReportNormalWithheldHintOnError(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	out := captureStdout(t, func() { Report(withheldData(OutcomeError)) })
	assert.Contains(t, out, "Dependency cooldown withheld 1 version during version resolution")
	assert.Contains(t, out, "@posthog/core")
	assert.Contains(t, out, "1.47.0 (available in 2 days)")
	assert.Contains(t, out, "this is the likely cause")
}

func TestReportNormalNoWithheldHintOnSuccess(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	data := withheldData(OutcomeSuccess)
	data.TotalAnalyzed = 2
	data.AllowedCount = 2

	out := captureStdout(t, func() { Report(data) })
	assert.NotContains(t, out, "withheld", "resolver fallback succeeded, hint would be noise")
}

func TestReportNormalErrorWithoutWithheldStaysQuiet(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	data := NewReportData()
	data.Outcome = OutcomeError

	out := captureStdout(t, func() { Report(data) })
	assert.Empty(t, out)
}

func TestReportNormalWithheldHintCapsVersions(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	data := NewReportData()
	data.Outcome = OutcomeError
	data.CooldownWithheldPackages = []models.CooldownWithheld{
		{Name: "busy-pkg", Versions: []models.CooldownWithheldVersion{
			{Version: "1.0.1", DaysLeft: 1},
			{Version: "1.0.2", DaysLeft: 2},
			{Version: "1.0.3", DaysLeft: 3},
			{Version: "1.0.4", DaysLeft: 4},
			{Version: "1.0.5", DaysLeft: 5},
		}},
	}

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "withheld 5 versions")
	assert.Contains(t, out, "1.0.3 (available in 3 days)")
	assert.NotContains(t, out, "1.0.4")
	assert.Contains(t, out, "and 2 more")
}

func TestReportSilentWithheldStaysQuiet(t *testing.T) {
	withVerbosity(t, VerbosityLevelSilent)

	out := captureStdout(t, func() { Report(withheldData(OutcomeError)) })
	assert.Empty(t, out)
}

func TestReportVerboseWithheldSection(t *testing.T) {
	withVerbosity(t, VerbosityLevelVerbose)

	out := captureStdout(t, func() { Report(withheldData(OutcomeError)) })
	assert.Contains(t, out, "Versions withheld by dependency cooldown:")
	assert.Contains(t, out, "@posthog/core@1.47.0")
	assert.Contains(t, out, "Available in 2 days")
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
