package packagemanager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

type GoDependencyResolverConfig struct {
	CommandName string
}

func NewDefaultGoDependencyResolverConfig() GoDependencyResolverConfig {
	return GoDependencyResolverConfig{
		CommandName: "go",
	}
}

type goCommandRunner func(context.Context, ...string) ([]byte, error)

type goDependencyResolver struct {
	// Go currently uses the common guard flow only, so this resolver exists to let
	// the guard resolve direct module targets while proxy interception support is pending.
	config  GoDependencyResolverConfig
	runJSON goCommandRunner
}

type goListModule struct {
	Path    string        `json:"Path"`
	Version string        `json:"Version"`
	Replace *goListModule `json:"Replace"`
}

var _ PackageResolver = &goDependencyResolver{}

func NewGoDependencyResolver(config GoDependencyResolverConfig) (*goDependencyResolver, error) {
	if config.CommandName == "" {
		config.CommandName = "go"
	}

	return &goDependencyResolver{
		config:  config,
		runJSON: defaultGoCommandRunner(config.CommandName),
	}, nil
}

func (r *goDependencyResolver) ResolveLatestVersion(ctx context.Context, pkg *packagev1.Package) (*packagev1.PackageVersion, error) {
	if pkg == nil || pkg.GetName() == "" {
		return nil, fmt.Errorf("package is required")
	}

	module, err := r.listModule(ctx, fmt.Sprintf("%s@latest", pkg.GetName()))
	if err != nil {
		return nil, ErrFailedToResolveVersion.Wrap(err)
	}

	if module.Version == "" {
		return nil, ErrFailedToResolveVersion.Wrap(fmt.Errorf("no version resolved for module %s", pkg.GetName()))
	}

	return &packagev1.PackageVersion{
		Package: pkg,
		Version: module.Version,
	}, nil
}

func (r *goDependencyResolver) ResolveDependencies(context.Context, *packagev1.PackageVersion) ([]*packagev1.PackageVersion, error) {
	return nil, nil
}

func (r *goDependencyResolver) listModule(ctx context.Context, target string) (*goListModule, error) {
	output, err := r.runJSON(ctx, "list", "-m", "-json", target)
	if err != nil {
		return nil, err
	}

	var module goListModule
	if err := json.Unmarshal(output, &module); err != nil {
		return nil, ErrFailedToParsePackage.Wrap(err)
	}

	if module.Replace != nil && module.Replace.Version != "" {
		return module.Replace, nil
	}

	return &module, nil
}

func defaultGoCommandRunner(commandName string) goCommandRunner {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, commandName, args...)

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			if stderr.Len() > 0 {
				return nil, fmt.Errorf("%w: %s", err, bytes.TrimSpace(stderr.Bytes()))
			}
			return nil, err
		}

		return stdout.Bytes(), nil
	}
}
