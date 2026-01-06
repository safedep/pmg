package interceptors

import (
	"os/exec"
	"syscall"

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
	// The caller receiving the response is responsible for closing this channel
	// after reading the response to prevent goroutine leaks.
	ResponseChan chan bool
}

// HandleConfirmationRequests processes confirmation requests sequentially
// This function should be run in a goroutine and will process requests
// from the confirmation channel one at a time, blocking on user input.
//
// The function will exit when the confirmation channel is closed.
func HandleConfirmationRequests(confirmationChan chan *ConfirmationRequest, interaction guard.PackageManagerGuardInteraction, cmd *exec.Cmd) {
	for req := range confirmationChan {
		func() {
			if cmd == nil || cmd.Process == nil {
				log.Errorf("Process not available to pause/resume for package %s", req.PackageVersion.GetPackage().GetName())
				// Default to blocking the package on missing process
				req.ResponseChan <- false
				return
			}

			// We must make sure to close the response channel to prevent goroutine leaks.
			defer func() {
				close(req.ResponseChan)
			}()

			// Pause the process to prompt user for confirmation
			if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
				log.Errorf("Error pausing process for package %s: %v\n", err, req.PackageVersion.GetPackage().GetName())
				return
			}

			packageName := req.PackageVersion.GetPackage().GetName()
			log.Debugf("Processing confirmation request for package %s", packageName)

			// Call the user interaction handler to get confirmation
			// This blocks waiting for stdin input
			confirmed, err := interaction.GetConfirmationOnMalware([]*analyzer.PackageVersionAnalysisResult{req.AnalysisResult})
			if err != nil {
				log.Errorf("Error getting confirmation for package %s: %v", packageName, err)
				// On error, default to blocking the package
				req.ResponseChan <- false
				return
			}

			log.Debugf("User response for package %s: confirmed=%v", packageName, confirmed)

			// Send the user's response back to the interceptor
			req.ResponseChan <- confirmed

			// Resume the process
			if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
				log.Errorf("Error resuming process for package %s: %v\n", err, req.PackageVersion.GetPackage().GetName())
				return
			}
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
