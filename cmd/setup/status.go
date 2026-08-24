package setup

import (
	"encoding/json"
	"io"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/analytics"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/internal/proxyserver"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/internal/version"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/truststore"
)

// Bump when the JSON contract changes so consumers (plugins, CI gates) can pin it.
const statusSchemaVersion = 1

type health string

const (
	healthProtected   health = "protected"
	healthDegraded    health = "degraded"
	healthUnprotected health = "unprotected"
)

type statusCheck struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Status   string `json:"status"` // pass | warn | fail
	Message  string `json:"message,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

type shimStatus struct {
	Installed bool   `json:"installed"`
	Dir       string `json:"dir,omitempty"`
}

type shellIntegration struct {
	Shell       string     `json:"shell"`
	Aliases     bool       `json:"aliases"`
	ShimsInPath bool       `json:"shims_in_path"`
	AliasRcFile string     `json:"alias_rc_file,omitempty"`
	UserShims   shimStatus `json:"user_shims"`
	SystemShims shimStatus `json:"system_shims"`
}

type cooldownInfo struct {
	Enabled bool `json:"enabled"`
	Days    int  `json:"days"`
}

type sandboxInfo struct {
	Enabled       bool              `json:"enabled"`
	Driver        string            `json:"driver"`
	Ready         bool              `json:"ready"`
	EnforceAlways bool              `json:"enforce_always"`
	Policies      map[string]string `json:"policies,omitempty"`
}

type caInfo struct {
	Trusted     bool   `json:"trusted"`
	Scope       string `json:"scope"` // none | user | system
	Expires     string `json:"expires,omitempty"`
	Installed   bool   `json:"installed"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type proxyInfo struct {
	Running    bool           `json:"running"`
	Addr       string         `json:"addr,omitempty"`
	PID        int            `json:"pid,omitempty"`
	Registries []registryInfo `json:"registries,omitempty"`
}

type registryInfo struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type protectionLayers struct {
	ThreatIntel bool         `json:"threat_intel"`
	Cooldown    cooldownInfo `json:"cooldown"`
	Sandbox     sandboxInfo  `json:"sandbox"`
	CA          caInfo       `json:"ca"`
	Proxy       proxyInfo    `json:"proxy"`
}

type configInfo struct {
	Path             string `json:"path"`
	Source           string `json:"source"` // user | global | global_locked
	ProxyInstallOnly bool   `json:"proxy_install_only"`
}

type securityInfo struct {
	TrustedPackages []string `json:"trusted_packages"`
	Telemetry       bool     `json:"telemetry"`
	EventLogging    bool     `json:"event_logging"`
	EventLogDir     string   `json:"event_log_dir,omitempty"`
}

type cloudInfo struct {
	Enabled     bool   `json:"enabled"`
	SyncDB      string `json:"sync_db,omitempty"`
	EndpointID  string `json:"endpoint_id,omitempty"`
	Credentials string `json:"credentials,omitempty"`
	AutoSync    string `json:"auto_sync,omitempty"`
	LastSync    string `json:"last_sync,omitempty"`
}

type statusReport struct {
	SchemaVersion int              `json:"schema_version"`
	Version       string           `json:"version"`
	Commit        string           `json:"commit"`
	Health        health           `json:"health"`
	Protected     bool             `json:"protected"`
	Config        configInfo       `json:"config"`
	Security      securityInfo     `json:"security"`
	Shell         shellIntegration `json:"shell_integration"`
	Layers        protectionLayers `json:"layers"`
	Cloud         *cloudInfo       `json:"cloud,omitempty"`
	Checks        []statusCheck    `json:"checks"`
}

type doctorSummary struct {
	Passed   int `json:"passed"`
	Warnings int `json:"warnings"`
	Failed   int `json:"failed"`
}

type doctorReport struct {
	statusReport
	Summary doctorSummary `json:"summary"`
}

func buildStatusReport(cfg *config.RuntimeConfig, checks []doctor.CheckResult) statusReport {
	h, protected := deriveStatus(checks, cfg.InsecureInstallation)

	return statusReport{
		SchemaVersion: statusSchemaVersion,
		Version:       version.Version,
		Commit:        version.Commit,
		Health:        h,
		Protected:     protected,
		Config:        collectConfigInfo(cfg),
		Security:      collectSecurityInfo(cfg),
		Shell:         collectShellIntegration(checks),
		Layers:        collectLayers(cfg),
		Cloud:         collectCloudInfo(cfg),
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

// Insecure installation allows every package without analysis, and a failing
// protection probe proves interception is bypassed: either forces "unprotected"
// even when aliases or shims are active. Otherwise a non-passing check is only
// "degraded", never "unprotected".
func deriveStatus(results []doctor.CheckResult, insecure bool) (health, bool) {
	if insecure || hasFailingProtectionCheck(results) || !isInterceptionActive(results) {
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

	aliasCfg := alias.DefaultConfig()
	rcFileManager, err := alias.NewDefaultRcFileManager(config.Get().ConfigDir(), aliasCfg.RcFileName)
	if err != nil {
		log.Debugf("rc file manager unavailable; omitting alias rc file: %v", err)
	} else {
		aliasManager := alias.New(aliasCfg, rcFileManager)
		installed, err := aliasManager.IsInstalled()
		if err != nil {
			log.Debugf("alias inspection failed; omitting alias rc file: %v", err)
		} else if installed {
			si.AliasRcFile = aliasManager.GetRcPath()
		}
	}

	userBinDir, err := shim.UserBinDir()
	if err != nil {
		userBinDir = ""
	}
	si.UserShims = shimStatus{Installed: shim.UserShimsInstalled(), Dir: userBinDir}
	si.SystemShims = shimStatus{Installed: shim.SystemShimsInstalled(), Dir: shim.SystemBinDir()}
	return si
}

func collectLayers(cfg *config.RuntimeConfig) protectionLayers {
	driver := resolveSandboxDriverName()

	layers := protectionLayers{
		// Insecure installation short-circuits analysis, so threat intel never runs.
		ThreatIntel: !cfg.InsecureInstallation,
		Cooldown: cooldownInfo{
			Enabled: cfg.Config.DependencyCooldown.Enabled,
			Days:    cfg.Config.DependencyCooldown.Days,
		},
		Sandbox: sandboxInfo{
			Enabled:       cfg.Config.Sandbox.Enabled,
			Driver:        driver,
			Ready:         driver != "unavailable",
			EnforceAlways: cfg.Config.Sandbox.EnforceAlways,
			Policies:      collectSandboxPolicies(cfg),
		},
		CA:    collectCAInfo(cfg),
		Proxy: collectProxyInfo(cfg),
	}
	return layers
}

func collectSandboxPolicies(cfg *config.RuntimeConfig) map[string]string {
	policies := cfg.Config.Sandbox.Policies
	if len(policies) == 0 {
		return nil
	}

	out := make(map[string]string, len(policies))
	for name := range policies {
		ref, _ := cfg.Config.Sandbox.PolicyFor(name)
		status := "disabled"
		if ref.Enabled {
			status = ref.Profile
		}
		out[name] = status
	}
	return out
}

func collectConfigInfo(cfg *config.RuntimeConfig) configInfo {
	source := "user"
	if cfg.IsManaged() {
		source = "global"
		if cfg.IsLocked() {
			source = "global_locked"
		}
	}

	return configInfo{
		Path:             cfg.ConfigFilePath(),
		Source:           source,
		ProxyInstallOnly: cfg.Config.Proxy.InstallOnly,
	}
}

func collectSecurityInfo(cfg *config.RuntimeConfig) securityInfo {
	purls := make([]string, 0, len(cfg.Config.TrustedPackages))
	for _, p := range cfg.Config.TrustedPackages {
		purls = append(purls, p.Purl)
	}

	return securityInfo{
		TrustedPackages: purls,
		Telemetry:       !analytics.IsDisabled(),
		EventLogging:    !cfg.Config.SkipEventLogging,
		EventLogDir:     cfg.EventLogDir(),
	}
}

func collectCloudInfo(cfg *config.RuntimeConfig) *cloudInfo {
	if !cfg.Config.Cloud.Enabled {
		return nil
	}

	return &cloudInfo{
		Enabled:     true,
		SyncDB:      cfg.CloudSyncDBPath(),
		EndpointID:  cfg.Config.Cloud.EndpointID,
		Credentials: describeCloudCredentials(),
		AutoSync:    describeAutoSync(cfg.Config.Cloud.AutoSync),
		LastSync:    describeLastSync(cfg.CloudSyncLastRunPath()),
	}
}

func collectCAInfo(cfg *config.RuntimeConfig) caInfo {
	// An unreadable cert makes on-disk expiry/trust untrustworthy; report the
	// layer as untrusted rather than encode contradictory data.
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

	ca := caInfo{Trusted: st.Trusted(), Scope: scope, Installed: st.KeyPresent && st.CertPresent}
	if st.CertPresent && !st.NotAfter.IsZero() {
		ca.Expires = st.NotAfter.Format(time.RFC3339)
	}
	if st.CertPresent {
		ca.Fingerprint = st.Fingerprint
	}
	return ca
}

func collectProxyInfo(cfg *config.RuntimeConfig) proxyInfo {
	info := proxyInfo{}
	if st := proxyserver.GetStatus(proxyserver.ResolveStatePath("", cfg.CacheDir())); st.Found && st.Running {
		info.Running = true
		info.Addr = st.Addr
		info.PID = st.PID
	}
	// Custom registries are surfaced even when the daemon is not running:
	// interception works per-command too.
	for _, r := range cfg.Config.Proxy.Registries {
		info.Registries = append(info.Registries, registryInfo{Name: r.Name, Ecosystem: string(r.Ecosystem)})
	}
	return info
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
