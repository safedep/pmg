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

func TestTermWidthFormatTextIndent(t *testing.T) {
	text := strings.Repeat("word ", 40)
	out := termWidthFormatTextIndent(text, 20, "    ")
	lines := strings.Split(out, "\n")
	require.Greater(t, len(lines), 1)
	for _, line := range lines[1:] {
		assert.True(t, strings.HasPrefix(line, "    "), "wrapped line must be indented: %q", line)
	}
}
