package runerror

import (
	"errors"
	"strings"
	"unicode/utf8"
)

const maxMessageBytes = 1024

type Source uint8

const (
	SourceUnspecified Source = iota
	SourcePMG
	SourceChildProcess
)

func (s Source) String() string {
	switch s {
	case SourcePMG:
		return "pmg"
	case SourceChildProcess:
		return "child_process"
	default:
		return "unspecified"
	}
}

type Reason uint8

const (
	ReasonUnspecified Reason = iota
	ReasonProcessExited
	ReasonProcessSignaled
	ReasonCommandParseFailed
	ReasonConfigurationInvalid
	ReasonEcosystemUnsupported
	ReasonCertificateSetupFailed
	ReasonAnalyzerInitializationFailed
	ReasonProxySetupFailed
	ReasonExecutableNotFound
	ReasonExecutableResolutionFailed
	ReasonProcessLaunchFailed
	ReasonExecutionSetupFailed
)

func (r Reason) String() string {
	switch r {
	case ReasonProcessExited:
		return "process_exited"
	case ReasonProcessSignaled:
		return "process_signaled"
	case ReasonCommandParseFailed:
		return "command_parse_failed"
	case ReasonConfigurationInvalid:
		return "configuration_invalid"
	case ReasonEcosystemUnsupported:
		return "ecosystem_unsupported"
	case ReasonCertificateSetupFailed:
		return "certificate_setup_failed"
	case ReasonAnalyzerInitializationFailed:
		return "analyzer_initialization_failed"
	case ReasonProxySetupFailed:
		return "proxy_setup_failed"
	case ReasonExecutableNotFound:
		return "executable_not_found"
	case ReasonExecutableResolutionFailed:
		return "executable_resolution_failed"
	case ReasonProcessLaunchFailed:
		return "process_launch_failed"
	case ReasonExecutionSetupFailed:
		return "execution_setup_failed"
	default:
		return "unspecified"
	}
}

type Info struct {
	Source   Source
	Reason   Reason
	Message  string
	ExitCode *uint32
}

type Reporter interface {
	ErrorInfo() Info
}

type reportedError struct {
	cause error
	info  Info
}

func (e *reportedError) Error() string   { return e.cause.Error() }
func (e *reportedError) Unwrap() error   { return e.cause }
func (e *reportedError) ErrorInfo() Info { return e.info }

func Wrap(err error, reason Reason) error {
	if err == nil {
		return nil
	}

	var reporter Reporter
	if errors.As(err, &reporter) {
		return err
	}

	source := sourceForReason(reason)
	message := ""
	if source == SourcePMG {
		message = cleanMessage(err.Error())
	}

	return &reportedError{
		cause: err,
		info: Info{
			Source:  source,
			Reason:  reason,
			Message: message,
		},
	}
}

func From(err error) *Info {
	if err == nil {
		return nil
	}

	var reporter Reporter
	if errors.As(err, &reporter) {
		info := reporter.ErrorInfo()
		info.Source = sourceForReason(info.Reason)
		info.Message = cleanMessage(info.Message)
		return &info
	}

	return nil
}

func sourceForReason(reason Reason) Source {
	switch reason {
	case ReasonProcessExited, ReasonProcessSignaled:
		return SourceChildProcess
	case ReasonCommandParseFailed,
		ReasonConfigurationInvalid,
		ReasonEcosystemUnsupported,
		ReasonCertificateSetupFailed,
		ReasonAnalyzerInitializationFailed,
		ReasonProxySetupFailed,
		ReasonExecutableNotFound,
		ReasonExecutableResolutionFailed,
		ReasonProcessLaunchFailed,
		ReasonExecutionSetupFailed:
		return SourcePMG
	default:
		return SourceUnspecified
	}
}

func cleanMessage(message string) string {
	message = strings.ToValidUTF8(message, "\uFFFD")
	if len(message) <= maxMessageBytes {
		return message
	}

	message = message[:maxMessageBytes]
	for !utf8.ValidString(message) {
		message = message[:len(message)-1]
	}
	return message
}
