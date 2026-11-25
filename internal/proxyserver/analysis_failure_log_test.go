package proxyserver

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func npmPackage(version string) *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, Name: "safedep-test-pkg"},
		Version: version,
	}
}

func TestAnalysisFailureLogWritesALine(t *testing.T) {
	for _, tc := range []struct {
		blocked bool
		action  string
	}{
		{blocked: false, action: "Allowed"},
		{blocked: true, action: "Blocked"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			var out bytes.Buffer
			l := newAnalysisFailureLog(&out)
			l.now = func() time.Time { return time.Date(2026, 11, 25, 5, 7, 34, 0, time.UTC) }

			l.Record(npmPackage("0.1.2"), status.Error(codes.DeadlineExceeded, "context deadline exceeded"), tc.blocked)

			assert.Equal(t, "2026-11-25T05:07:34Z "+tc.action+" pkg:npm/safedep-test-pkg@0.1.2 without malware analysis: "+
				"rpc error: code = DeadlineExceeded desc = context deadline exceeded\n", out.String())
		})
	}
}

func TestAnalysisFailureLogRemovesControlCharacters(t *testing.T) {
	var out bytes.Buffer
	l := newAnalysisFailureLog(&out)
	l.now = func() time.Time { return time.Date(2026, 11, 25, 5, 7, 34, 0, time.UTC) }

	forged := status.Error(codes.Unavailable,
		"bad\n2026-11-25T05:07:35Z Allowed pkg:npm/forged@1.0.0 without malware analysis\x1b[2J")
	l.Record(npmPackage("0.1.2"), forged, false)

	assert.Equal(t, 1, strings.Count(out.String(), "\n"), "the error text cannot start a new line")
	assert.NotContains(t, out.String(), "\x1b")
	assert.Contains(t, out.String(), "desc = bad2026-11-25T05:07:35Z Allowed pkg:npm/forged@1.0.0")
}

func TestAnalysisFailureLogLimitsABurst(t *testing.T) {
	var out bytes.Buffer
	now := time.Date(2026, 11, 25, 5, 0, 0, 0, time.UTC)
	l := newAnalysisFailureLog(&out)
	l.now = func() time.Time { return now }

	failure := fmt.Errorf("circuit breaker is open")
	for i := range analysisFailureMaxLines + 5 {
		l.Record(npmPackage(fmt.Sprintf("1.0.%d", i)), failure, false)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, analysisFailureMaxLines)

	now = now.Add(analysisFailureWindow)
	l.Record(npmPackage("2.0.0"), failure, false)

	lines = strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, analysisFailureMaxLines+2)
	assert.Contains(t, lines[analysisFailureMaxLines], "pmg did not write 5 more lines")
	assert.Contains(t, lines[analysisFailureMaxLines+1], "pkg:npm/safedep-test-pkg@2.0.0")
}

func TestAnalysisFailureLogFlushWritesTheHeldBackCount(t *testing.T) {
	for _, tc := range []struct {
		blocked bool
		line    string
	}{
		{blocked: false, line: "pmg did not write 3 more lines about packages allowed without malware analysis"},
		{blocked: true, line: "pmg did not write 3 more lines about packages blocked without malware analysis"},
	} {
		t.Run(fmt.Sprintf("blocked=%t", tc.blocked), func(t *testing.T) {
			var out bytes.Buffer
			l := newAnalysisFailureLog(&out)

			failure := fmt.Errorf("circuit breaker is open")
			for i := range analysisFailureMaxLines + 3 {
				l.Record(npmPackage(fmt.Sprintf("1.0.%d", i)), failure, tc.blocked)
			}
			l.Flush()
			l.Flush()

			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			require.Len(t, lines, analysisFailureMaxLines+1)
			assert.Contains(t, lines[analysisFailureMaxLines], tc.line)
		})
	}
}
