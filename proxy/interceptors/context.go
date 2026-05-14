package interceptors

import packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"

// InterceptorContext carries execution metadata for request-time policy decisions.
type InterceptorContext struct {
	PinnedVersions []*packagev1.PackageVersion
}
