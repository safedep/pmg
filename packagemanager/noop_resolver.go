package packagemanager

import (
	"context"
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// noopPackageResolver satisfies PackageResolver for flows that never resolve
// dependencies up front, such as the proxy flow where every download is
// intercepted and analyzed on the wire.
type noopPackageResolver struct{}

func NewNoopPackageResolver() PackageResolver {
	return noopPackageResolver{}
}

func (noopPackageResolver) ResolveLatestVersion(context.Context, *packagev1.Package) (*packagev1.PackageVersion, error) {
	return nil, fmt.Errorf("package resolution is not supported by the noop resolver")
}

func (noopPackageResolver) ResolveDependencies(context.Context, *packagev1.PackageVersion) ([]*packagev1.PackageVersion, error) {
	return nil, fmt.Errorf("dependency resolution is not supported by the noop resolver")
}
