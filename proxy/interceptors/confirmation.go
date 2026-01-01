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
	ResponseChan   chan bool // Channel to send the user's response back
}

// HandleConfirmationRequests processes confirmation requests sequentially
// This function should be run in a goroutine and will process requests
// from the confirmation channel one at a time, blocking on user input.
//
// The function will exit when the confirmation channel is closed.
func HandleConfirmationRequests(confirmationChan chan *ConfirmationRequest, interaction guard.PackageManagerGuardInteraction) {
	for req := range confirmationChan {
		packageName := req.PackageVersion.GetPackage().GetName()
		log.Debugf("Processing confirmation request for package %s", packageName)

		// Call the user interaction handler to get confirmation
		// This blocks waiting for stdin input
		confirmed, err := interaction.GetConfirmationOnMalware([]*analyzer.PackageVersionAnalysisResult{req.AnalysisResult})
		if err != nil {
			log.Errorf("Error getting confirmation for package %s: %v", packageName, err)
			// On error, default to blocking the package
			req.ResponseChan <- false
			continue
		}

		log.Debugf("User response for package %s: confirmed=%v", packageName, confirmed)

		// Send the user's response back to the interceptor
		req.ResponseChan <- confirmed
	}

	log.Debugf("Confirmation handler exiting (channel closed)")
}

// NewConfirmationRequest creates a new confirmation request with a response channel
func NewConfirmationRequest(pkgVersion *packagev1.PackageVersion, result *analyzer.PackageVersionAnalysisResult) *ConfirmationRequest {
	return &ConfirmationRequest{
		PackageVersion: pkgVersion,
		AnalysisResult: result,
		ResponseChan:   make(chan bool, 1), // Buffered channel to avoid blocking
	}
}
