package interceptors

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These tests cover how the install gate reacts to a backend that gives no
// verdict. The gate fails closed. Retry behavior for transient errors is a
// backend-layer concern and is covered in the analyzer package.
//
// The gate applies this policy when the backend gives no verdict:
//   - Any analysis error: block the install (fail closed).
//   - NotFound (package not in the database): allow the install. Do not retry.

// The gate gets an unknown backend error. The gate must block the install.
func TestNpmRegistry_UnknownAnalyzerError_ShouldFailClosed(t *testing.T) {
	mock := &mockAnalyzer{err: status.Error(codes.Internal, "backend exploded")}
	interceptor := newTestNpmCustomInterceptor(t, mock, "https://packages.test/npm")

	// The tarball path starts the analysis.
	ctx := makeTestRequestContext("https://packages.test/npm/demo/-/demo-1.2.3.tgz")
	resp, err := interceptor.HandleRequest(ctx)
	require.NoError(t, err)

	assert.Equal(t, proxy.ActionBlock, resp.Action,
		"an unknown backend error must block the install")
	assert.Equal(t, proxy.BlockReasonAnalysisUnavailable, resp.BlockReason)
}

// The package is not in the analysis database. The gate must allow the install.
// The gate must not retry.
func TestAnalyzePackage_NotFound_AllowsWithoutRetry(t *testing.T) {
	mock := &mockAnalyzer{err: status.Error(codes.NotFound, "package not found")}
	base := newTestBaseInterceptor(mock)
	ctx := newTestRequestContext()

	result, err := base.analyzePackage(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "pkg", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, analyzer.ActionAllow, result.Action)
	assert.Equal(t, 1, mock.callCount, "the gate must not retry NotFound")
}
