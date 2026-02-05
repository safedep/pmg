package interceptors

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
)

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

func TestBaseRegistryInterceptor_HandleAnalysisResult_ParanoidTreatsSuspiciousAsBlocked(t *testing.T) {
	cfg := config.Get()
	ogParanoid := cfg.Config.Paranoid
	cfg.Config.Paranoid = true

	defer func() {
		cfg.Config.Paranoid = ogParanoid
	}()

	confirmationChan := make(chan *ConfirmationRequest, 1)

	base := &baseRegistryInterceptor{
		confirmationChan: confirmationChan,
	}

	parsedURL, _ := url.Parse("https://registry.npmjs.org/test")
	ctx := &proxy.RequestContext{
		URL: parsedURL,
		Method: "GET",
		Headers: make(http.Header),
		RequestID: "test-req-id",
		StartTime: time.Now(),
		Data: make(map[string]interface{}),
	}

	result := &analyzer.PackageVersionAnalysisResult{
		Action: analyzer.ActionConfirm,
		Summary: "Suspicious behaviour detected",
		ReferenceURL: "https://example.com/suspicious-report",
	}

	response, err := base.handleAnalysisResult(
		ctx,
		packagev1.Ecosystem_ECOSYSTEM_NPM,
		"suspicious-pkg",
		"2.0.0",
		result,
	)

	assert.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, response.Action)
	assert.Equal(t, http.StatusForbidden, response.BlockCode)
	assert.NotEmpty(t, response.BlockMessage)

	// this ensures we didn't ask for user confirmation in paranoid mode
	select {
	case <- confirmationChan:
		t.Fatalf("expected no confirmation request in paranoid mode")
	default:	
	}
}	