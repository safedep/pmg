package proxye2e

import (
	"sync"

	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/guard"
)

// ConfirmController drives the suspicious-package confirmation prompt. The
// default policy denies, matching PMG's safe default for an unhandled prompt.
type ConfirmController struct {
	mu      sync.Mutex
	policy  func([]*analyzer.PackageVersionAnalysisResult) (bool, error)
	prompts [][]string
}

func newConfirmController() *ConfirmController {
	return &ConfirmController{policy: func([]*analyzer.PackageVersionAnalysisResult) (bool, error) { return false, nil }}
}

func (c *ConfirmController) AutoApprove() {
	c.setPolicy(func([]*analyzer.PackageVersionAnalysisResult) (bool, error) { return true, nil })
}

func (c *ConfirmController) AutoDeny() {
	c.setPolicy(func([]*analyzer.PackageVersionAnalysisResult) (bool, error) { return false, nil })
}

func (c *ConfirmController) Func(fn func([]*analyzer.PackageVersionAnalysisResult) (bool, error)) {
	c.setPolicy(fn)
}

func (c *ConfirmController) setPolicy(fn func([]*analyzer.PackageVersionAnalysisResult) (bool, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy = fn
}

// Prompts returns the package names presented for confirmation, one entry per prompt.
func (c *ConfirmController) Prompts() [][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]string, len(c.prompts))
	copy(out, c.prompts)
	return out
}

func (c *ConfirmController) interaction() *guard.PackageManagerGuardInteraction {
	return &guard.PackageManagerGuardInteraction{
		GetConfirmationOnMalware: func(pkgs []*analyzer.PackageVersionAnalysisResult) (bool, error) {
			names := make([]string, 0, len(pkgs))
			for _, p := range pkgs {
				names = append(names, p.PackageVersion.GetPackage().GetName())
			}

			c.mu.Lock()
			c.prompts = append(c.prompts, names)
			policy := c.policy
			c.mu.Unlock()

			return policy(pkgs)
		},
	}
}
