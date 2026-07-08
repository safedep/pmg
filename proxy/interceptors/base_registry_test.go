package interceptors

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	pmgconfig "github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setTrustedPackagesForTest(t *testing.T, pkgs []pmgconfig.TrustedPackage) {
	t.Helper()
	orig := pmgconfig.Get().Config.TrustedPackages
	pmgconfig.Get().Config.TrustedPackages = pkgs
	require.NoError(t, pmgconfig.PreprocessPackageRefs(&pmgconfig.Get().Config), "setTrustedPackagesForTest: preprocess")
	t.Cleanup(func() {
		pmgconfig.Get().Config.TrustedPackages = orig
		assert.NoError(t, pmgconfig.PreprocessPackageRefs(&pmgconfig.Get().Config))
	})
}

func setBlockedPackagesForTest(t *testing.T, pkgs []pmgconfig.BlockedPackage) {
	t.Helper()
	orig := pmgconfig.Get().Config.Block.Packages
	pmgconfig.Get().Config.Block.Packages = pkgs
	require.NoError(t, pmgconfig.PreprocessPackageRefs(&pmgconfig.Get().Config), "setBlockedPackagesForTest: preprocess")
	t.Cleanup(func() {
		pmgconfig.Get().Config.Block.Packages = orig
		assert.NoError(t, pmgconfig.PreprocessPackageRefs(&pmgconfig.Get().Config))
	})
}

func TestPolicyGate_TrustedReturnsAllow(t *testing.T) {
	setTrustedPackagesForTest(t, []pmgconfig.TrustedPackage{{Purl: "pkg:npm/trusted-pkg"}})

	b := &baseRegistryInterceptor{}
	ctx := makeTestRequestContext("https://registry.npmjs.org/trusted-pkg/-/trusted-pkg-1.0.0.tgz")

	resp, ok := b.policyGate(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "trusted-pkg", "1.0.0")
	require.True(t, ok)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
}

func TestPolicyGate_UntrustedReturnsFalse(t *testing.T) {
	setTrustedPackagesForTest(t, nil)

	b := &baseRegistryInterceptor{}
	ctx := makeTestRequestContext("https://registry.npmjs.org/x/-/x-1.0.0.tgz")

	resp, ok := b.policyGate(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "x", "1.0.0")
	assert.False(t, ok)
	assert.Nil(t, resp)
}

func TestPolicyGate_InsecureReturnsAllow(t *testing.T) {
	orig := pmgconfig.Get().InsecureInstallation
	pmgconfig.Get().InsecureInstallation = true
	t.Cleanup(func() { pmgconfig.Get().InsecureInstallation = orig })

	b := &baseRegistryInterceptor{}
	ctx := makeTestRequestContext("https://registry.npmjs.org/any-pkg/-/any-pkg-1.0.0.tgz")

	resp, ok := b.policyGate(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "any-pkg", "1.0.0")
	require.True(t, ok)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
}

func TestPolicyGate_BlocklistedReturnsBlock(t *testing.T) {
	setBlockedPackagesForTest(t, []pmgconfig.BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "deprecated internally"}})

	stats := NewAnalysisStatsCollector()
	b := &baseRegistryInterceptor{statsCollector: stats}
	ctx := makeTestRequestContext("https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz")

	resp, ok := b.policyGate(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "left-pad", "1.0.0")
	require.True(t, ok)
	assert.Equal(t, proxy.ActionBlock, resp.Action)
	assert.Equal(t, http.StatusForbidden, resp.BlockCode)
	assert.Contains(t, resp.BlockMessage, "block.packages")
	assert.Contains(t, resp.BlockMessage, "deprecated internally")
	assert.Equal(t, 1, stats.GetStats().BlocklistBlockedCount)

	blocks := stats.GetBlocklistBlocks()
	require.Len(t, blocks, 1)
	assert.Equal(t, "left-pad", blocks[0].Name)
	assert.Equal(t, "1.0.0", blocks[0].Version)
	assert.Equal(t, "deprecated internally", blocks[0].Reason)
}

func TestPolicyGate_BlockWinsOverTrust(t *testing.T) {
	setTrustedPackagesForTest(t, []pmgconfig.TrustedPackage{{Purl: "pkg:npm/left-pad"}})
	setBlockedPackagesForTest(t, []pmgconfig.BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "banned"}})

	b := &baseRegistryInterceptor{}
	ctx := makeTestRequestContext("https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz")

	resp, ok := b.policyGate(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "left-pad", "1.0.0")
	require.True(t, ok)
	assert.Equal(t, proxy.ActionBlock, resp.Action)
}

func TestPolicyGate_InsecureWinsOverBlocklist(t *testing.T) {
	setBlockedPackagesForTest(t, []pmgconfig.BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "banned"}})

	orig := pmgconfig.Get().InsecureInstallation
	pmgconfig.Get().InsecureInstallation = true
	t.Cleanup(func() { pmgconfig.Get().InsecureInstallation = orig })

	b := &baseRegistryInterceptor{}
	ctx := makeTestRequestContext("https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz")

	resp, ok := b.policyGate(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "left-pad", "1.0.0")
	require.True(t, ok)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
}

func TestPolicyGate_BlocklistReasonOmittedWhenEmpty(t *testing.T) {
	setBlockedPackagesForTest(t, []pmgconfig.BlockedPackage{{Purl: "pkg:npm/left-pad"}})

	b := &baseRegistryInterceptor{}
	ctx := makeTestRequestContext("https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz")

	resp, ok := b.policyGate(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "left-pad", "1.0.0")
	require.True(t, ok)
	assert.NotContains(t, resp.BlockMessage, "Reason:")
}

func TestBaseRegistryInterceptor_HandleAnalysisResult(t *testing.T) {
	tests := []struct {
		name               string
		ecosystem          packagev1.Ecosystem
		packageName        string
		packageVersion     string
		analysisResult     *analyzer.PackageVersionAnalysisResult
		userConfirms       bool
		expectedAction     proxy.ResponseAction
		expectedBlockCode  int
		expectBlockMessage bool
	}{
		{
			name:           "ActionBlock - malicious package",
			ecosystem:      packagev1.Ecosystem_ECOSYSTEM_NPM,
			packageName:    "malicious-pkg",
			packageVersion: "1.0.0",
			analysisResult: &analyzer.PackageVersionAnalysisResult{
				Action:       analyzer.ActionBlock,
				Summary:      "Contains known malware",
				ReferenceURL: "https://example.com/malware-report",
			},
			expectedAction:     proxy.ActionBlock,
			expectedBlockCode:  http.StatusForbidden,
			expectBlockMessage: true,
		},
		{
			name:           "ActionConfirm - user confirms installation",
			ecosystem:      packagev1.Ecosystem_ECOSYSTEM_NPM,
			packageName:    "suspicious-pkg",
			packageVersion: "2.0.0",
			analysisResult: &analyzer.PackageVersionAnalysisResult{
				Action:       analyzer.ActionConfirm,
				Summary:      "Suspicious behavior detected",
				ReferenceURL: "https://example.com/suspicious-report",
			},
			userConfirms:       true,
			expectedAction:     proxy.ActionAllow,
			expectedBlockCode:  0,
			expectBlockMessage: false,
		},
		{
			name:           "ActionConfirm - user declines installation",
			ecosystem:      packagev1.Ecosystem_ECOSYSTEM_NPM,
			packageName:    "suspicious-pkg",
			packageVersion: "2.0.0",
			analysisResult: &analyzer.PackageVersionAnalysisResult{
				Action:       analyzer.ActionConfirm,
				Summary:      "Suspicious behavior detected",
				ReferenceURL: "https://example.com/suspicious-report",
			},
			userConfirms:       false,
			expectedAction:     proxy.ActionBlock,
			expectedBlockCode:  http.StatusForbidden,
			expectBlockMessage: true,
		},
		// Note: Timeout test case is skipped as it would require waiting 5 minutes
		// The timeout behavior is covered by the implementation but not tested here
		// to keep tests fast
		{
			name:           "ActionAllow - safe package",
			ecosystem:      packagev1.Ecosystem_ECOSYSTEM_NPM,
			packageName:    "safe-pkg",
			packageVersion: "3.0.0",
			analysisResult: &analyzer.PackageVersionAnalysisResult{
				Action:       analyzer.ActionAllow,
				Summary:      "Package is safe",
				ReferenceURL: "https://example.com/safe-report",
			},
			expectedAction:     proxy.ActionAllow,
			expectedBlockCode:  0,
			expectBlockMessage: false,
		},
		{
			name:           "ActionUnknown - default to allow",
			ecosystem:      packagev1.Ecosystem_ECOSYSTEM_NPM,
			packageName:    "unknown-pkg",
			packageVersion: "4.0.0",
			analysisResult: &analyzer.PackageVersionAnalysisResult{
				Action:       analyzer.ActionUnknown,
				Summary:      "Unknown action",
				ReferenceURL: "https://example.com/unknown-report",
			},
			expectedAction:     proxy.ActionAllow,
			expectedBlockCode:  0,
			expectBlockMessage: false,
		},
		{
			name:           "ActionBlock - pypi ecosystem",
			ecosystem:      packagev1.Ecosystem_ECOSYSTEM_PYPI,
			packageName:    "malicious-pypi-pkg",
			packageVersion: "5.0.0",
			analysisResult: &analyzer.PackageVersionAnalysisResult{
				Action:       analyzer.ActionBlock,
				Summary:      "Malicious PyPI package",
				ReferenceURL: "https://example.com/pypi-malware",
			},
			expectedAction:     proxy.ActionBlock,
			expectedBlockCode:  http.StatusForbidden,
			expectBlockMessage: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confirmationChan := make(chan *ConfirmationRequest, 1)

			base := &baseRegistryInterceptor{
				confirmationChan: confirmationChan,
			}

			parsedURL, _ := url.Parse("https://registry.npmjs.org/test")
			ctx := &proxy.RequestContext{
				URL:       parsedURL,
				Method:    "GET",
				Headers:   make(http.Header),
				RequestID: "test-request-id",
				StartTime: time.Now(),
				Data:      make(map[string]interface{}),
			}

			if tt.analysisResult.Action == analyzer.ActionConfirm {
				go func() {
					req := <-confirmationChan
					req.ResponseChan <- tt.userConfirms
					close(req.ResponseChan)
				}()
			}

			response, err := base.handleAnalysisResult(
				ctx,
				tt.ecosystem,
				tt.packageName,
				tt.packageVersion,
				tt.analysisResult,
			)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedAction, response.Action)
			assert.Equal(t, tt.expectedBlockCode, response.BlockCode)
			assert.Equal(t, tt.expectBlockMessage, response.BlockMessage != "")
		})
	}
}

func TestAppendCustomMessage(t *testing.T) {
	assert.Equal(t, "base", appendCustomMessage("base", ""))
	assert.Equal(t, "base\n\ncustom", appendCustomMessage("base", "custom"))
}

func TestHandleAnalysisResultBlockCarriesMalwareMessage(t *testing.T) {
	origMsg := pmgconfig.Get().Config.Block.Message
	pmgconfig.Get().Config.Block.Message = "Contact #security-help"
	t.Cleanup(func() { pmgconfig.Get().Config.Block.Message = origMsg })

	b := &baseRegistryInterceptor{}
	ctx := makeTestRequestContext("https://registry.npmjs.org/evil/-/evil-1.0.0.tgz")

	result := &analyzer.PackageVersionAnalysisResult{
		PackageVersion: &packagev1.PackageVersion{
			Package: &packagev1.Package{Name: "evil", Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
			Version: "1.0.0",
		},
		Action:  analyzer.ActionBlock,
		Summary: "verified malware",
	}

	resp, err := b.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "evil", "1.0.0", result)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, resp.Action)
	assert.Contains(t, resp.BlockMessage, "Contact #security-help")
}
