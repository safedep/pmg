//go:build linux || darwin

package platform

import (
	"fmt"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
	"github.com/safedep/pmg/sandbox/util"
)

func expandAll(patterns []string) ([]string, error) {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		expanded, err := util.ExpandVariables(p)
		if err != nil {
			return nil, fmt.Errorf("failed to expand pattern %q: %w", p, err)
		}
		out = append(out, expanded)
	}
	return out, nil
}

// mandatoryDenySet is the mandatory deny patterns of a policy, with the
// expanded allow_read list that suppressed some of them.
type mandatoryDenySet struct {
	util.MandatoryDenyResult
	expandedAllowRead []string
}

// mandatoryDenies returns the mandatory deny patterns of policy, and logs
// each one that an explicit allow rule of policy suppresses.
func mandatoryDenies(policy *sandbox.SandboxPolicy) (mandatoryDenySet, error) {
	expandedAllowRead, err := expandAll(policy.Filesystem.AllowRead)
	if err != nil {
		log.Warnf("sandbox: failed to expand allow_read for mandatory deny suppression, all mandatory denies preserved: %v", err)
		expandedAllowRead = nil
	}
	expandedAllowWrite, err := expandAll(policy.Filesystem.AllowWrite)
	if err != nil {
		log.Warnf("sandbox: failed to expand allow_write for mandatory deny suppression, all mandatory denies preserved: %v", err)
		expandedAllowWrite = nil
	}

	result, err := util.GetMandatoryDenyPatterns(util.MandatoryDenyOptions{
		AllowGitConfig: utils.SafelyGetValue(policy.AllowGitConfig),
		AllowRead:      expandedAllowRead,
		AllowWrite:     expandedAllowWrite,
	})
	if err != nil {
		return mandatoryDenySet{}, fmt.Errorf("failed to compute mandatory denies: %w", err)
	}

	for _, p := range result.SuppressedRead {
		log.Warnf("sandbox: mandatory deny %q suppressed for read by explicit allow rule in policy %q", p, policy.Name)
	}
	for _, p := range result.SuppressedWrite {
		log.Warnf("sandbox: mandatory deny %q suppressed for write by explicit allow rule in policy %q", p, policy.Name)
	}

	return mandatoryDenySet{MandatoryDenyResult: result, expandedAllowRead: expandedAllowRead}, nil
}
