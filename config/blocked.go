package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/safedep/dry/policy/match"
	"github.com/safedep/dry/policy/pbidentity"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

// BlockedPackage is one entry of blocked_packages. pmg blocks each artifact
// that it selects, whatever the verdict of the malware analysis is.
type BlockedPackage struct {
	// Purl selects one package, one version of a package, or every package
	// under a prefix that ends with "/*" or ".*".
	Purl string `mapstructure:"purl"`

	// Vers is an optional version range in the vers form, as in
	// "vers:npm/>=1.2.0|<2.0.0". A Purl with a version takes no range.
	Vers string `mapstructure:"vers"`

	// Reason shows in the block message.
	Reason string `mapstructure:"reason"`
}

// localRuleIDPrefix starts the id of each blocked_packages rule.
const localRuleIDPrefix = "local:"

// BlockedPackagesError is an entry of blocked_packages that pmg cannot read.
// It fails the load closed, because a block that pmg drops is a block that
// does not apply.
type BlockedPackagesError struct {
	err error
}

func (e *BlockedPackagesError) Error() string {
	return fmt.Sprintf("invalid blocked_packages: %v", e.err)
}

func (e *BlockedPackagesError) Unwrap() error {
	return e.err
}

// BlockedPackageRules returns the package rules of blocked_packages. Each rule
// has the id "local:" and the first 12 hex characters of the SHA-256 of the
// PURL, a newline and the range, so the id does not change when the order of
// the list changes.
func BlockedPackageRules(entries []BlockedPackage) ([]match.Rule, error) {
	rules := make([]match.Rule, 0, len(entries))
	var errs []error
	for i, entry := range entries {
		rule := match.Rule{
			ID:     LocalRuleID(entry.Purl, entry.Vers),
			Effect: match.EffectBlock,
			PURL:   entry.Purl,
			Vers:   entry.Vers,
			Reason: entry.Reason,
			Origin: match.Origin{Kind: match.OriginLocal},
		}

		if entry.Purl == "" {
			errs = append(errs, fmt.Errorf("entry %d: purl is required", i+1))
			continue
		}
		if err := match.Validate(rule, pbidentity.Identity{}); err != nil {
			errs = append(errs, fmt.Errorf("entry %d (%s): %w", i+1, entry.Purl, err))
			continue
		}
		rules = append(rules, rule)
	}

	if len(errs) > 0 {
		return nil, &BlockedPackagesError{err: errors.Join(errs...)}
	}
	return rules, nil
}

// parseBlockedPackages parses blocked_packages into the rules of cfg. pmg
// parses the list once for each config load, and every reader takes the
// rules from RuntimeConfig.BlockedRules.
func parseBlockedPackages(cfg *Config) error {
	rules, err := BlockedPackageRules(cfg.BlockedPackages)
	if err != nil {
		cfg.blockedRules = nil
		return err
	}
	cfg.blockedRules = rules
	return nil
}

// BlockedRules returns the rules of blocked_packages, with the active config
// file as their origin. A block message names that file.
func (r *RuntimeConfig) BlockedRules() []match.Rule {
	rules := make([]match.Rule, len(r.Config.blockedRules))
	for i, rule := range r.Config.blockedRules {
		rule.Origin.Path = r.configFilePath
		rules[i] = rule
	}
	return rules
}

// LocalRuleID returns the rule id of a blocked_packages entry.
func LocalRuleID(purl, vers string) string {
	sum := sha256.Sum256([]byte(purl + "\n" + vers))
	return localRuleIDPrefix + hex.EncodeToString(sum[:])[:12]
}

// NewInvalidBlockedPackagesError turns a BlockedPackagesError into the error
// that the CLI reports.
func NewInvalidBlockedPackagesError(err error) error {
	detail := err
	var blockedErr *BlockedPackagesError
	if errors.As(err, &blockedErr) {
		detail = blockedErr.Unwrap()
	}

	return usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidBlockedPackages).
		WithHumanError(fmt.Sprintf("invalid blocked_packages configuration: %v", detail)).
		WithHelp("Fix the blocked_packages entries, or the field that the error names, in your PMG configuration file, then retry.").
		Wrap(err)
}
