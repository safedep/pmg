package packagemanager

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
)

type GoDependencyResolverConfig struct {
	IncludeTransitiveDependencies bool
	TransitiveDepth               int
}

func NewDefaultGoDependencyResolverConfig() GoDependencyResolverConfig {
	return GoDependencyResolverConfig{
		IncludeTransitiveDependencies: true,
		TransitiveDepth:               5,
	}
}

type goDependencyResolver struct {
	config GoDependencyResolverConfig
}

var _ PackageResolver = &goDependencyResolver{}

func NewGoDependencyResolver(config GoDependencyResolverConfig) (*goDependencyResolver, error) {
	return &goDependencyResolver{
		config: config,
	}, nil
}

func (r *goDependencyResolver) ResolveLatestVersion(ctx context.Context,
	pkg *packagev1.Package) (*packagev1.PackageVersion, error) {
	
	// Query Go proxy for latest version
	// Note: In a real implementation, we'd use a more robust way to handle module paths
	url := fmt.Sprintf("https://proxy.golang.org/%s/@latest", pkg.Name)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, ErrFailedToFetchPackage.Wrap(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrPackageNotFound.Wrap(fmt.Errorf("status code: %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Body is JSON like {"Version":"v1.2.3","Time":"..."}
	version := ""
	if strings.Contains(string(body), "\"Version\":\"") {
		parts := strings.Split(string(body), "\"Version\":\"")
		if len(parts) > 1 {
			version = strings.Split(parts[1], "\"")[0]
		}
	}

	if version == "" {
		return nil, ErrFailedToResolveVersion.Wrap(fmt.Errorf("could not find version in response"))
	}

	log.Debugf("Resolved go/%s to latest version %s", pkg.Name, version)

	return &packagev1.PackageVersion{
		Package: pkg,
		Version: version,
	}, nil
}

func (r *goDependencyResolver) ResolveDependencies(ctx context.Context,
	packageVersion *packagev1.PackageVersion) ([]*packagev1.PackageVersion, error) {
	
	// Transitive dependency resolution for Go is complex and usually requires 
	// a full Go toolchain or a sophisticated go.mod parser.
	// For this initial implementation, we return an empty list or just the package itself
	// if we wanted to be conservative.
	
	
	// TODO: Implement transitive dependency resolution for Go
	return []*packagev1.PackageVersion{}, nil
}
