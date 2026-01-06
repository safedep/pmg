package interceptors

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/guard"
)

// ConfirmationRequest represents a request for user confirmation on a suspicious package
type ConfirmationRequest struct {
	PackageVersion *packagev1.PackageVersion
	AnalysisResult *analyzer.PackageVersionAnalysisResult

	// ResponseChan is used to send the user's response back.
	ResponseChan chan bool
}

// ConfirmationHook is a set of hooks that can be used to customize the confirmation process.
type ConfirmationHook struct {
	// BeforeInteraction is called before the user interaction is started.
	BeforeInteraction func([]*analyzer.PackageVersionAnalysisResult) error

	// AfterInteraction is called after the user interaction is finished.
	AfterInteraction func([]*analyzer.PackageVersionAnalysisResult, bool) error
}

// HandleConfirmationRequests processes confirmation requests sequentially
// This function should be run in a goroutine and will process requests
// from the confirmation channel one at a time, blocking on user input.
//
// The function will exit when the confirmation channel is closed.
func HandleConfirmationRequests(confirmationChan chan *ConfirmationRequest,
	interaction guard.PackageManagerGuardInteraction, hooks *ConfirmationHook) {
	if hooks == nil {
		hooks = &ConfirmationHook{}
	}

	for req := range confirmationChan {
		func() {
			// We must make sure to close the response channel to prevent goroutine leaks.
			// Idiomatic go suggests that the writer should close the channel.
			defer func() {
				close(req.ResponseChan)
			}()

			packageName := req.PackageVersion.GetPackage().GetName()
			log.Debugf("Processing confirmation request for package %s", packageName)

			if hooks.BeforeInteraction != nil {
				if err := hooks.BeforeInteraction([]*analyzer.PackageVersionAnalysisResult{req.AnalysisResult}); err != nil {
					log.Errorf("Error before interaction for package %s: %v", packageName, err)
					req.ResponseChan <- false
					return
				}
			}

			// Call the user interaction handler to get confirmation
			// This blocks waiting for stdin input
			confirmed, confirmationErr := interaction.GetConfirmationOnMalware([]*analyzer.PackageVersionAnalysisResult{req.AnalysisResult})

			// Must guarantee to call the after interaction hook regardless of the confirmation error.
			if hooks.AfterInteraction != nil {
				if err := hooks.AfterInteraction([]*analyzer.PackageVersionAnalysisResult{req.AnalysisResult}, confirmed); err != nil {
					log.Errorf("Error after interaction for package %s: %v", packageName, err)
				}
			}

			if confirmationErr != nil {
				log.Errorf("Error getting confirmation for package %s: %v", packageName, confirmationErr)
				req.ResponseChan <- false
				return
			}

			// Send the user's response back to the interceptor
			req.ResponseChan <- confirmed
		}()
	}

	log.Debugf("Confirmation handler exiting (channel closed)")
}

// NewConfirmationRequest creates a new confirmation request with a response channel
func NewConfirmationRequest(pkgVersion *packagev1.PackageVersion, result *analyzer.PackageVersionAnalysisResult) *ConfirmationRequest {
	return &ConfirmationRequest{
		PackageVersion: pkgVersion,
		AnalysisResult: result,
		ResponseChan:   make(chan bool, 1),
	}
}
