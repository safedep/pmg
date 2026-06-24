package errcodes

const (
	InvalidArgument               = "InvalidArgument"
	PermissionDenied              = "PermissionDenied"
	NotFound                      = "NotFound"
	Timeout                       = "Timeout"
	Canceled                      = "Canceled"
	UnexpectedEOF                 = "UnexpectedEOF"
	Lifecycle                     = "Lifecycle"
	Network                       = "Network"
	PackageManagerExecutionFailed = "PackageManagerExecutionFailed"
	BubblewrapNotFound            = "BubblewrapNotFound"

	// Package manager error codes.
	DependencyResolutionFailed = "DependencyResolutionFailed"
	PackageParseFailed         = "PackageParseFailed"
	PackageAuthorNotFound      = "PackageAuthorNotFound"
	GitHubRateLimitExceeded    = "GitHubRateLimitExceeded"

	// Certificate trust store error codes.
	CertGeneration      = "CertGeneration"
	CertPersistence     = "CertPersistence"
	CertTrustStore      = "CertTrustStore"
	UnsupportedPlatform = "UnsupportedPlatform"

	// Proxy error codes. ProxyPolicyViolation is returned when the proxy blocked
	// one or more packages by policy (malware, dependency cooldown, or a denied
	// suspicious package) and the run was gated with --fail-on-violation.
	ProxyPolicyViolation = "ProxyPolicyViolation"

	// Unknown mirrors the default code that dry/usefulerror returns for errors
	// created without an explicit code, so unset and explicitly-unknown errors
	// classify identically (e.g. the bug-report hint in ui.ErrorExit).
	Unknown = "unknown"
)
