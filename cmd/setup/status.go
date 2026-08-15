package setup

import (
	"encoding/json"
	"io"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/internal/version"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/truststore"
)

// statusSchemaVersion versions the JSON contract emitted by
// `pmg setup info --json` and `pmg setup doctor --json` so consumers (the
// Omarchy plugin, CI gates) can pin behaviour across PMG releases.
const statusSchemaVersion = 1

type health string

const (
	healthProtected   health = "protected"
	healthDegraded    health = "degraded"
	healthUnprotected health = "unprotected"
)

// statusCheck is the JSON projection of a doctor.CheckResult.
type statusCheck struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Status   string `json:"status"` // pass | warn | fail
	Message  string `json:"message,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

type shellIntegration struct {
	Shell       string `json:"shell"`
	Aliases     bool   `json:"aliases"`
	ShimsInPath bool   `json:"shims_in_path"`
}

type cooldownInfo struct {
	Enabled bool `json:"enabled"`
	Days    int  `json:"days"`
}

type sandboxInfo struct {
	Enabled bool   `json:"enabled"`
	Driver  string `json:"driver"`
	Ready   bool   `json:"ready"`
}

type caInfo struct {
	Trusted bool   `json:"trusted"`
	Scope   string `json:"scope"` // none | user | system
	Expires string `json:"expires,omitempty"`
}

type proxyInfo struct {
	Running bool   `json:"running"`
	Addr    string `json:"addr,omitempty"`
	PID     int    `json:"pid,omitempty"`
}

type protectionLayers struct {
	ThreatIntel bool         `json:"threat_intel"`
	Cooldown    cooldownInfo `json:"cooldown"`
	Sandbox     sandboxInfo  `json:"sandbox"`
	CA          caInfo       `json:"ca"`
	Proxy       proxyInfo    `json:"proxy"`
}

// statusReport is the machine-readable protection status shared by
// `pmg setup info --json` and `pmg setup doctor --json`: a health/protected
// verdict, the enabled layers, and the checks it was derived from.
type statusReport struct {
	SchemaVersion int              `json:"schema_version"`
	Version       string           `json:"version"`
	Health        health           `json:"health"`
	Protected     bool             `json:"protected"`
	Shell         shellIntegration `json:"shell_integration"`
	Layers        protectionLayers `json:"layers"`
	Checks        []statusCheck    `json:"checks"`
}

type doctorSummary struct {
	Passed   int `json:"passed"`
	Warnings int `json:"warnings"`
	Failed   int `json:"failed"`
}

// doctorReport is emitted by `pmg setup doctor --json`: the full status report
// (with the authoritative interception probes in Checks) plus a pass/warn/fail
// summary. It is a superset of the info report and is the surface a CI gate
// should trust.
type doctorReport struct {
	statusReport
	Summary doctorSummary `json:"summary"`
}

// buildStatusReport rolls a set of checks and the current config into the shared
// status report. The caller chooses which checks to pass: the cheap core checks
// for `setup info`, or core plus the authoritative probes for `setup doctor`.
func buildStatusReport(cfg *config.RuntimeConfig, checks []doctor.CheckResult) statusReport {
	h, protected := deriveStatus(checks)

	return statusReport{
		SchemaVersion: statusSchemaVersion,
		Version:       version.Version,
		Health:        h,
		Protected:     protected,
		Shell:         collectShellIntegration(checks),
		Layers:        collectLayers(cfg),
		Checks:        toStatusChecks(checks),
	}
}

func collectInfoReport(cfg *config.RuntimeConfig) statusReport {
	return buildStatusReport(cfg, runCoreChecks(cfg))
}

func buildDoctorReport(cfg *config.RuntimeConfig, results []doctor.CheckResult) doctorReport {
	passed, warnings, failed := countStatuses(results)

	return doctorReport{
		statusReport: buildStatusReport(cfg, results),
		Summary:      doctorSummary{Passed: passed, Warnings: warnings, Failed: failed},
	}
}

// deriveStatus rolls a set of checks into a single verdict. Protected is the
// security-critical signal: are installs actually intercepted. A failing
// authoritative protection probe (present only in the doctor report) proves
// interception is bypassed and forces "unprotected", overriding the presence of
// aliases or shims. Otherwise any non-passing check downgrades an intercepting
// install to "degraded" without claiming it is unprotected.
func deriveStatus(results []doctor.CheckResult) (health, bool) {
	if hasFailingProtectionCheck(results) || !isInterceptionActive(results) {
		return healthUnprotected, false
	}
	for _, r := range results {
		if r.Status != doctor.StatusPass {
			return healthDegraded, true
		}
	}
	return healthProtected, true
}

func hasFailingProtectionCheck(results []doctor.CheckResult) bool {
	for _, r := range results {
		if r.Category == categoryProtection && r.Status == doctor.StatusFail {
			return true
		}
	}
	return false
}

func collectShellIntegration(core []doctor.CheckResult) shellIntegration {
	shell, err := alias.DetectShell()
	if err != nil {
		shell = "unknown"
	}

	si := shellIntegration{Shell: shell}
	if c, ok := findCheck(core, checkShellAliases); ok {
		si.Aliases = c.ImpliesInterception
	}
	if c, ok := findCheck(core, checkShimInPath); ok {
		si.ShimsInPath = c.Status == doctor.StatusPass
	}
	return si
}

func collectLayers(cfg *config.RuntimeConfig) protectionLayers {
	driver := resolveSandboxDriverName()

	layers := protectionLayers{
		ThreatIntel: true,
		Cooldown: cooldownInfo{
			Enabled: cfg.Config.DependencyCooldown.Enabled,
			Days:    cfg.Config.DependencyCooldown.Days,
		},
		Sandbox: sandboxInfo{
			Enabled: cfg.Config.Sandbox.Enabled,
			Driver:  driver,
			Ready:   driver != "unavailable",
		},
		CA:    collectCAInfo(cfg),
		Proxy: collectProxyInfo(cfg),
	}
	return layers
}

func collectCAInfo(cfg *config.RuntimeConfig) caInfo {
	// A present-but-unreadable/malformed cert makes the on-disk metadata
	// (expiry, trust) untrustworthy; the ca-cert check already reports the
	// failure, so here we report the layer as untrusted rather than encode
	// contradictory data.
	st, err := certmanager.InspectCA(cfg.ConfigDir())
	if err != nil {
		log.Debugf("CA inspection failed; reporting CA layer as untrusted: %v", err)
		return caInfo{Scope: "none"}
	}
	st.UserTrusted, st.SystemTrusted, _ = truststore.Status(certmanager.CACommonName)

	scope := "none"
	if st.SystemTrusted {
		scope = "system"
	} else if st.UserTrusted {
		scope = "user"
	}

	ca := caInfo{Trusted: st.Trusted(), Scope: scope}
	if st.CertPresent && !st.NotAfter.IsZero() {
		ca.Expires = st.NotAfter.Format(time.RFC3339)
	}
	return ca
}

func collectProxyInfo(cfg *config.RuntimeConfig) proxyInfo {
	st := proxyserver.GetStatus(proxyserver.ResolveStatePath("", cfg.CacheDir()))
	if !st.Found || !st.Running {
		return proxyInfo{}
	}
	return proxyInfo{Running: true, Addr: st.Addr, PID: st.PID}
}

func toStatusChecks(results []doctor.CheckResult) []statusCheck {
	checks := make([]statusCheck, 0, len(results))
	for _, r := range results {
		checks = append(checks, statusCheck{
			Name:     r.Name,
			Category: r.Category,
			Status:   statusString(r.Status),
			Message:  r.Message,
			Fix:      fixFor(r),
		})
	}
	return checks
}

// fixFor returns the actionable fix for a non-passing check, preferring a
// result-specific override over the static hint. Passing checks have no fix.
func fixFor(r doctor.CheckResult) string {
	if r.Status == doctor.StatusPass {
		return ""
	}
	if r.Fix != "" {
		return r.Fix
	}
	return checkFixes[r.Name]
}

func statusString(s doctor.CheckStatus) string {
	switch s {
	case doctor.StatusPass:
		return "pass"
	case doctor.StatusWarn:
		return "warn"
	case doctor.StatusFail:
		return "fail"
	default:
		return "unknown"
	}
}

func countStatuses(results []doctor.CheckResult) (passed, warnings, failed int) {
	for _, r := range results {
		switch r.Status {
		case doctor.StatusPass:
			passed++
		case doctor.StatusWarn:
			warnings++
		case doctor.StatusFail:
			failed++
		}
	}
	return passed, warnings, failed
}

func findCheck(results []doctor.CheckResult, name string) (doctor.CheckResult, bool) {
	for _, r := range results {
		if r.Name == name {
			return r, true
		}
	}
	return doctor.CheckResult{}, false
}

func writeStatusJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
