// Package cloudpolicy is the cloud layer of pmg: the policy cache, the
// binding table and the package rule index.
package cloudpolicy

import (
	"fmt"
	"math"
	"time"

	"github.com/safedep/pmg/config"
)

const (
	// PathMinAge is the contract path of the dependency cooldown.
	PathMinAge = "package_admission.cooldown.min_age"

	// PathPackageRules is the contract path of the package rules. They map to
	// no pmg key. They go into the package rule index.
	PathPackageRules = "core.package_rules"

	keyCooldownEnabled = "dependency_cooldown.enabled"
	keyCooldownDays    = "dependency_cooldown.days"
)

// binding is one row of the binding table: a contract path, the pmg keys
// that it sets, and the transform. The row shape is the shape that
// dry/policy/bind takes later.
type binding struct {
	path  string
	keys  []string
	label string

	// apply sets the pmg keys from the value of the path in the value tree.
	apply func(cfg *config.Config, value any) error
}

// bindings is the binding table of pmg. core.package_rules has no row with
// keys: the package rule index applies it. scan_gate is a capability that
// pmg does not implement.
var bindings = []binding{
	{
		path:  PathMinAge,
		keys:  []string{keyCooldownEnabled, keyCooldownDays},
		label: "the dependency cooldown",
		apply: applyMinAge,
	},
}

// implementedCapabilities are the capabilities of the contract that pmg
// applies. A field of these capabilities that the contract marks
// binding_required must have a row, or the package rule index.
var implementedCapabilities = map[string]bool{
	"core":              true,
	"package_admission": true,
}

// applyMinAge turns the cooldown on when min_age is above zero and sets the
// window in days, rounded up. A min_age of zero turns the cooldown off.
func applyMinAge(cfg *config.Config, value any) error {
	minAge, ok := value.(time.Duration)
	if !ok {
		return fmt.Errorf("%s: unexpected value type %T", PathMinAge, value)
	}
	if minAge < 0 {
		return fmt.Errorf("%s: negative duration %s", PathMinAge, minAge)
	}

	days := math.Ceil(minAge.Hours() / 24)
	if days > math.MaxInt32 {
		return fmt.Errorf("%s: duration %s is too large", PathMinAge, minAge)
	}

	cfg.DependencyCooldown.Enabled = minAge > 0
	cfg.DependencyCooldown.Days = int(days)
	return nil
}
