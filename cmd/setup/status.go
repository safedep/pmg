package setup

import (
	"encoding/json"
	"io"
	"time"

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

// infoReport is the machine-readable protection status emitted by
// `pmg setup info --json`. It is derived only from the cheap core checks and
// config, so it is safe to poll (no interception probes are executed).
type infoReport struct {
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

// doctorReport is emitted by `pmg setup doctor --json`. Unlike infoReport it
// includes the authoritative interception probes, so it is the report a CI gate
// should trust.
type doctorReport struct {
	SchemaVersion int           `json:"schema_version"`
	Version       string        `json:"version"`
	Health        health        `json:"health"`
	Protected     bool          `json:"protected"`
	Summary       doctorSummary `json:"summary"`
	Checks        []statusCheck `json:"checks"`
}

func collectInfoReport(cfg *config.RuntimeConfig) infoReport {
	core := runCoreChecks(cfg)
	h, protected := deriveStatus(core)

	return infoReport{
		SchemaVersion: statusSchemaVersion,
		Version:       version.Version,
		Health:        h,
		Protected:     protected,
		Shell:         collectShellIntegration(core),
		Layers:        collectLayers(cfg),
		Checks:        toStatusChecks(core),
	}
}

func buildDoctorReport(results []doctor.CheckResult) doctorReport {
	h, protected := deriveStatus(results)
	passed, warnings, failed := countStatuses(results)

	return doctorReport{
		SchemaVersion: statusSchemaVersion,
		Version:       version.Version,
		Health:        h,
		Protected:     protected,
		Summary:       doctorSummary{Passed: passed, Warnings: warnings, Failed: failed},
		Checks:        toStatusChecks(results),
	}
}

// deriveStatus rolls a set of checks into a single verdict. Protected is the
// security-critical signal: are installs actually intercepted (via aliases or
// shims on PATH). Health layers on the rest: any non-passing check downgrades an
// intercepting install to "degraded" without claiming it is unprotected.
func deriveStatus(results []doctor.CheckResult) (health, bool) {
	if !isInterceptionActive(results) {
		return healthUnprotected, false
	}
	for _, r := range results {
		if r.Status != doctor.StatusPass {
			return healthDegraded, true
		}
	}
	return healthProtected, true
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
	st, _ := certmanager.InspectCA(cfg.ConfigDir())
	st.UserTrusted, st.SystemTrusted, _ = truststore.Status(certmanager.CACommonName)

	scope := "none"
	if st.SystemTrusted {
		scope = "system"
	} else if st.UserTrusted {
		scope = "user"
	}

	ca := caInfo{Trusted: st.Trusted(), Scope: scope}
	if st.CertPresent {
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
