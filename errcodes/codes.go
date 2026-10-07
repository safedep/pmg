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
	PackageManagerNotFound        = "PackageManagerNotFound"
	BubblewrapNotFound            = "BubblewrapNotFound"

	// Package manager error codes.
	PackageParseFailed      = "PackageParseFailed"
	PackageAuthorNotFound   = "PackageAuthorNotFound"
	GitHubRateLimitExceeded = "GitHubRateLimitExceeded"

	// Certificate trust store error codes.
	CertGeneration      = "CertGeneration"
	CertPersistence     = "CertPersistence"
	CertTrustStore      = "CertTrustStore"
	UnsupportedPlatform = "UnsupportedPlatform"

	// Sandbox error codes. SandboxRequiresProxy is returned when a sandbox
	// policy enables network_via_proxy_only but no PMG proxy is running to
	// confine traffic to.
	SandboxRequiresProxy = "SandboxRequiresProxy"
	// SandboxPolicyDisabled is returned when `pmg sandbox exec` finds its
	// policy disabled in the config. The command never runs unsandboxed.
	SandboxPolicyDisabled = "SandboxPolicyDisabled"
	// SandboxPolicyInvalid is returned when a sandbox policy cannot be
	// enforced as written, for example outbound rules without lockdown.
	SandboxPolicyInvalid = "SandboxPolicyInvalid"

	// Proxy error codes. ProxyPolicyViolation is returned when the proxy blocked
	// one or more packages by policy (malware, dependency cooldown, or a denied
	// suspicious package) and the run was gated with --fail-on-violation.
	// InvalidProxyRegistries is returned when proxy.registries fails
	// validation, so PMG aborts startup rather than running unprotected.
	ProxyPolicyViolation   = "ProxyPolicyViolation"
	InvalidProxyRegistries = "InvalidProxyRegistries"

	// Enforce error codes. EnforceRequirements is returned when the host
	// cannot attach the kernel programs: a missing capability, no kernel
	// BTF, or no cgroup v2. EnforceRequiresTrustedCA is returned when the
	// PMG CA is not in the system trust store, which every enforced client
	// depends on.
	EnforceRequirements      = "EnforceRequirements"
	EnforceRequiresTrustedCA = "EnforceRequiresTrustedCA"
	EnforceAlreadyActive     = "EnforceAlreadyActive"

	// Cloud error codes. CloudCredentialsNotFound is returned when a cloud
	// operation needs SafeDep Cloud credentials but none are configured in the
	// keychain or environment.
	CloudCredentialsNotFound = "CloudCredentialsNotFound"

	// Unknown mirrors the default code that dry/usefulerror returns for errors
	// created without an explicit code, so unset and explicitly-unknown errors
	// classify identically (e.g. the bug-report hint in ui.ErrorExit).
	Unknown = "unknown"
)
