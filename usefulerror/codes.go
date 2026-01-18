package usefulerror

// Standard error codes that can be re-used across the project.
// We will use a human friendly format for the error codes and not align with posix error codes.
// Keep this minimal. Reuse first before adding new ones.
const (
	ErrCodeInvalidArgument               = "InvalidArgument"
	ErrCodePermissionDenied              = "PermissionDenied"
	ErrCodeNotFound                      = "NotFound"
	ErrCodeTimeout                       = "Timeout"
	ErrCodeCanceled                      = "Canceled"
	ErrCodeUnexpectedEOF                 = "UnexpectedEOF"
	ErrCodeUnknown                       = "Unknown"
	ErrCodeLifecycle                     = "Lifecycle"
	ErrCodeNetwork                       = "Network"
	ErrCodePackageManagerExecutionFailed = "PackageManagerExecutionFailed"
)
