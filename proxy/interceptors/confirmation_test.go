package interceptors

import (
	"errors"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/guard"
	"github.com/stretchr/testify/assert"
)

func mockPackageVersion(name, version string) *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{Name: name},
		Version: version,
	}
}

func mockAnalysisResult() *analyzer.PackageVersionAnalysisResult {
	return &analyzer.PackageVersionAnalysisResult{
		Action:  analyzer.ActionConfirm,
		Summary: "Test suspicious package",
	}
}

func TestHandleConfirmationRequests(t *testing.T) {
	tests := []struct {
		name                 string
		confirmationResponse bool
		confirmationError    error
		beforeInteractionErr error
		afterInteractionErr  error
		useNilHooks          bool
		expectedResponse     bool
		verifyHooksCalled    bool
	}{
		{
			name:                 "user confirms installation",
			confirmationResponse: true,
			confirmationError:    nil,
			useNilHooks:          false,
			expectedResponse:     true,
			verifyHooksCalled:    true,
		},
		{
			name:                 "user denies installation",
			confirmationResponse: false,
			confirmationError:    nil,
			useNilHooks:          false,
			expectedResponse:     false,
			verifyHooksCalled:    true,
		},
		{
			name:                 "confirmation error returns false",
			confirmationResponse: false,
			confirmationError:    errors.New("confirmation failed"),
			useNilHooks:          false,
			expectedResponse:     false,
			verifyHooksCalled:    true,
		},
		{
			name:                 "before interaction hook error is non-fatal",
			confirmationResponse: true,
			confirmationError:    nil,
			beforeInteractionErr: errors.New("before hook failed"),
			useNilHooks:          false,
			expectedResponse:     true,
			verifyHooksCalled:    true,
		},
		{
			name:                 "after interaction hook error is non-fatal",
			confirmationResponse: true,
			confirmationError:    nil,
			afterInteractionErr:  errors.New("after hook failed"),
			useNilHooks:          false,
			expectedResponse:     true,
			verifyHooksCalled:    true,
		},
		{
			name:                 "nil hooks does not panic",
			confirmationResponse: true,
			confirmationError:    nil,
			useNilHooks:          true,
			expectedResponse:     true,
			verifyHooksCalled:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforeCalled := false
			afterCalled := false
			var afterConfirmedParam bool

			interaction := guard.PackageManagerGuardInteraction{
				GetConfirmationOnMalware: func(results []*analyzer.PackageVersionAnalysisResult) (bool, error) {
					assert.Len(t, results, 1)
					return tt.confirmationResponse, tt.confirmationError
				},
			}

			var hooks *ConfirmationHook
			if !tt.useNilHooks {
				hooks = &ConfirmationHook{
					BeforeInteraction: func(results []*analyzer.PackageVersionAnalysisResult) error {
						beforeCalled = true
						assert.Len(t, results, 1)
						return tt.beforeInteractionErr
					},
					AfterInteraction: func(results []*analyzer.PackageVersionAnalysisResult, confirmed bool) error {
						afterCalled = true
						afterConfirmedParam = confirmed
						assert.Len(t, results, 1)
						return tt.afterInteractionErr
					},
				}
			}

			confirmationChan := make(chan *ConfirmationRequest, 1)
			go HandleConfirmationRequests(confirmationChan, interaction, hooks)

			pkgVersion := mockPackageVersion("test-package", "1.0.0")
			analysisResult := mockAnalysisResult()
			analysisResult.PackageVersion = pkgVersion
			req := NewConfirmationRequest(pkgVersion, analysisResult)
			confirmationChan <- req

			response := <-req.ResponseChan

			assert.Equal(t, tt.expectedResponse, response)

			if tt.verifyHooksCalled {
				assert.True(t, beforeCalled, "BeforeInteraction hook should be called")
				assert.True(t, afterCalled, "AfterInteraction hook should be called")
				if tt.confirmationError == nil {
					assert.Equal(t, tt.confirmationResponse, afterConfirmedParam,
						"AfterInteraction should receive correct confirmation status")
				}
			} else {
				assert.False(t, beforeCalled, "BeforeInteraction hook should not be called when hooks are nil")
				assert.False(t, afterCalled, "AfterInteraction hook should not be called when hooks are nil")
			}

			close(confirmationChan)
		})
	}
}

func TestHandleConfirmationRequests_MultipleSequential(t *testing.T) {
	processedPackages := []string{}

	interaction := guard.PackageManagerGuardInteraction{
		GetConfirmationOnMalware: func(results []*analyzer.PackageVersionAnalysisResult) (bool, error) {
			pkgName := results[0].PackageVersion.GetPackage().GetName()
			processedPackages = append(processedPackages, pkgName)
			return true, nil
		},
	}

	confirmationChan := make(chan *ConfirmationRequest, 3)
	go HandleConfirmationRequests(confirmationChan, interaction, nil)

	pkgVersion1 := mockPackageVersion("package-1", "1.0.0")
	analysisResult1 := mockAnalysisResult()
	analysisResult1.PackageVersion = pkgVersion1
	req1 := NewConfirmationRequest(pkgVersion1, analysisResult1)

	pkgVersion2 := mockPackageVersion("package-2", "1.0.0")
	analysisResult2 := mockAnalysisResult()
	analysisResult2.PackageVersion = pkgVersion2
	req2 := NewConfirmationRequest(pkgVersion2, analysisResult2)

	pkgVersion3 := mockPackageVersion("package-3", "1.0.0")
	analysisResult3 := mockAnalysisResult()
	analysisResult3.PackageVersion = pkgVersion3
	req3 := NewConfirmationRequest(pkgVersion3, analysisResult3)

	confirmationChan <- req1
	confirmationChan <- req2
	confirmationChan <- req3

	response1 := <-req1.ResponseChan
	response2 := <-req2.ResponseChan
	response3 := <-req3.ResponseChan

	assert.True(t, response1)
	assert.True(t, response2)
	assert.True(t, response3)

	assert.Equal(t, []string{"package-1", "package-2", "package-3"}, processedPackages)

	close(confirmationChan)
}

func TestNewConfirmationRequest(t *testing.T) {
	pkgVersion := mockPackageVersion("test-package", "1.0.0")
	analysisResult := mockAnalysisResult()
	analysisResult.PackageVersion = pkgVersion

	req := NewConfirmationRequest(pkgVersion, analysisResult)

	assert.NotNil(t, req)
	assert.Equal(t, pkgVersion, req.PackageVersion)
	assert.Equal(t, analysisResult, req.AnalysisResult)
	assert.NotNil(t, req.ResponseChan)
	assert.Equal(t, 1, cap(req.ResponseChan), "ResponseChan should have buffer size of 1")
}
