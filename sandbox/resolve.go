package sandbox

import (
	"fmt"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox/util"
)

// ResolveProfile loads name via the registry, resolves inheritance, and
// returns a SandboxPolicy with all path-bearing fields expanded against opts
// (or process env where opts fields are empty). The returned policy is a deep
// copy — the registry-cached policy is never mutated.
func (r *defaultProfileRegistry) ResolveProfile(name string, opts ResolveOptions) (*SandboxPolicy, error) {
	policy, err := r.GetProfile(name)
	if err != nil {
		return nil, err
	}

	resolved, err := expandPolicyPaths(policy, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to expand variables for profile %s: %w", name, err)
	}

	return resolved, nil
}

func expandPolicyPaths(p *SandboxPolicy, opts ResolveOptions) (*SandboxPolicy, error) {
	// Shallow struct copy aliases *bool pointers with the registry-cached
	// policy. Re-point them so callers mutating the result can't corrupt the
	// cache. Slice fields below are rebuilt fresh so they're already isolated.
	out := *p
	if p.AllowGitConfig != nil {
		out.AllowGitConfig = utils.PtrTo(*p.AllowGitConfig)
	}
	if p.AllowPTY != nil {
		out.AllowPTY = utils.PtrTo(*p.AllowPTY)
	}
	if p.AllowNetworkBind != nil {
		out.AllowNetworkBind = utils.PtrTo(*p.AllowNetworkBind)
	}

	allowRead, err := expandSlice(p.Filesystem.AllowRead, opts)
	if err != nil {
		return nil, err
	}
	allowWrite, err := expandSlice(p.Filesystem.AllowWrite, opts)
	if err != nil {
		return nil, err
	}
	denyRead, err := expandSlice(p.Filesystem.DenyRead, opts)
	if err != nil {
		return nil, err
	}
	denyWrite, err := expandSlice(p.Filesystem.DenyWrite, opts)
	if err != nil {
		return nil, err
	}
	out.Filesystem = FilesystemPolicy{
		AllowRead:  allowRead,
		AllowWrite: allowWrite,
		DenyRead:   denyRead,
		DenyWrite:  denyWrite,
	}

	allowExec, err := expandSlice(p.Process.AllowExec, opts)
	if err != nil {
		return nil, err
	}
	denyExec, err := expandSlice(p.Process.DenyExec, opts)
	if err != nil {
		return nil, err
	}
	out.Process = ProcessPolicy{AllowExec: allowExec, DenyExec: denyExec}

	// Network entries are host:port and don't carry path variables, but the
	// slices are still deep-copied so the caller can safely mutate the result.
	out.Network = NetworkPolicy{
		AllowOutbound: append([]string(nil), p.Network.AllowOutbound...),
		DenyOutbound:  append([]string(nil), p.Network.DenyOutbound...),
		AllowBind:     append([]string(nil), p.Network.AllowBind...),
	}

	// Environment entries are variable-name globs, not paths, so they are
	// deep-copied without expansion so the caller can safely mutate the result.
	out.Environment = EnvironmentPolicy{
		Allow: append([]string(nil), p.Environment.Allow...),
		Deny:  append([]string(nil), p.Environment.Deny...),
	}

	out.PackageManagers = append([]string(nil), p.PackageManagers...)

	return &out, nil
}

func expandSlice(in []string, opts ResolveOptions) ([]string, error) {
	if in == nil {
		return nil, nil
	}

	out := make([]string, len(in))
	for i, p := range in {
		exp, err := util.ExpandVariablesWith(p, opts.CWD, opts.Home, opts.TmpDir)
		if err != nil {
			return nil, err
		}
		out[i] = exp
	}

	return out, nil
}
