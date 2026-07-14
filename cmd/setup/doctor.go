package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/internal/fsutil"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/internal/version"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/sandbox/platform"
	"github.com/safedep/pmg/truststore"
	"github.com/spf13/cobra"
)

const (
	checkConfigFile         = "config-file"
	checkEventLogDir        = "event-log-dir"
	checkShellAliases       = "shell-aliases"
	checkShimDirectory      = "shim-directory"
	checkShimInPath         = "shim-in-path"
	checkProxyMode          = "proxy-mode"
	checkDependencyCooldown = "dependency-cooldown"
	checkEventLogging       = "event-logging"
	checkSandbox            = "sandbox"
	checkProtectionNpm      = "protection-npm"
	checkProtectionPip      = "protection-pip"
	checkCA                 = "ca-cert"
	checkSystemBinary       = "system-binary"

	aliasesInstalledMessage = "Shell aliases installed"
)

func NewDoctorCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "doctor",
		Short:        "Validate PMG installation and protection",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))
			err := executeDoctorChecks()
			if _, ok := err.(*doctorFailError); ok {
				cmd.SilenceErrors = true
			}
			return err
		},
	}
}

type doctorFailError struct{}

func (e *doctorFailError) Error() string { return "" }
func (e *doctorFailError) ExitCode() int { return 1 }

func executeDoctorChecks() error {
	cfg := config.Get()

	coreResults := runCoreChecks(cfg)
	protectionResults := runProtectionChecks(coreResults)
	allResults := append(coreResults, protectionResults...)

	printResults(allResults)

	if doctor.HasFailures(allResults) {
		return &doctorFailError{}
	}
	return nil
}

func runCoreChecks(cfg *config.RuntimeConfig) []doctor.CheckResult {
	checks := []doctor.Check{
		{
			Name:     checkConfigFile,
			Category: "Configuration",
			Run: func() doctor.CheckResult {
				if _, err := os.Stat(cfg.ConfigFilePath()); err != nil {
					return doctor.CheckResult{
						Status:  doctor.StatusFail,
						Message: "Config file not found",
					}
				}
				return doctor.CheckResult{
					Status:  doctor.StatusPass,
					Message: "Config file found",
				}
			},
		},
		{
			Name:     checkEventLogDir,
			Category: "Configuration",
			Run: func() doctor.CheckResult {
				return checkEventLogDirResult(cfg.Config.SkipEventLogging, cfg.EventLogDir(), cfg.ConfigDir())
			},
		},
		{
			Name:     checkShellAliases,
			Category: "Shell Integration",
			Run: func() doctor.CheckResult {
				aliasCfg := alias.DefaultConfig()
				rcFileManager, err := alias.NewDefaultRcFileManager(aliasCfg.RcFileName)
				if err != nil {
					return doctor.CheckResult{
						Status:  doctor.StatusWarn,
						Message: fmt.Sprintf("Could not check aliases: %v", err),
					}
				}
				aliasManager := alias.New(aliasCfg, rcFileManager)
				installed, err := aliasManager.IsInstalled()
				if err != nil {
					return doctor.CheckResult{
						Status:  doctor.StatusWarn,
						Message: fmt.Sprintf("Could not determine alias status: %v", err),
					}
				}
				if installed {
					return doctor.CheckResult{
						Status:              doctor.StatusPass,
						Message:             aliasesInstalledMessage,
						ImpliesInterception: true,
					}
				}
				if shim.SystemShimsInstalled() {
					return doctor.CheckResult{
						Status:  doctor.StatusPass,
						Message: "No aliases (system install)",
					}
				}
				return doctor.CheckResult{
					Status:  doctor.StatusFail,
					Message: "Aliases not installed",
				}
			},
		},
		{
			Name:     checkShimDirectory,
			Category: "Shell Integration",
			Run: func() doctor.CheckResult {
				if shim.SystemShimsInstalled() {
					return doctor.CheckResult{
						Status:  doctor.StatusPass,
						Message: fmt.Sprintf("System shim directory found (%s)", shim.SystemBinDir()),
					}
				}
				sm, err := shim.NewDefaultShimManager()
				if err != nil {
					return doctor.CheckResult{
						Status:  doctor.StatusWarn,
						Message: fmt.Sprintf("Could not check shims: %v", err),
					}
				}
				shimDir := sm.GetBinDir()
				info, err := os.Stat(shimDir)
				if err != nil || !info.IsDir() {
					return doctor.CheckResult{
						Status:  doctor.StatusFail,
						Message: "Shim directory not found",
					}
				}
				return doctor.CheckResult{
					Status:  doctor.StatusPass,
					Message: "Shim directory found",
				}
			},
		},
		{
			Name:     checkShimInPath,
			Category: "Shell Integration",
			Run:      checkShimInPathResult,
		},
		{
			Name:     checkProxyMode,
			Category: "Security",
			Run: func() doctor.CheckResult {
				if cfg.IsProxyModeEnabled() {
					return doctor.CheckResult{
						Status:  doctor.StatusPass,
						Message: "Proxy mode is enabled",
					}
				}
				return doctor.CheckResult{
					Status:  doctor.StatusFail,
					Message: "Proxy mode is disabled",
				}
			},
		},
		{
			Name:     checkDependencyCooldown,
			Category: "Security",
			Run: func() doctor.CheckResult {
				if cfg.Config.DependencyCooldown.Enabled {
					return doctor.CheckResult{
						Status:  doctor.StatusPass,
						Message: "Dependency cooldown is enabled",
					}
				}
				return doctor.CheckResult{
					Status:  doctor.StatusWarn,
					Message: "Dependency cooldown is disabled",
				}
			},
		},
		{
			Name:     checkEventLogging,
			Category: "Security",
			Run: func() doctor.CheckResult {
				if !cfg.Config.SkipEventLogging {
					return doctor.CheckResult{
						Status:  doctor.StatusPass,
						Message: "Event logging is enabled",
					}
				}
				return doctor.CheckResult{
					Status:  doctor.StatusWarn,
					Message: "Event logging is disabled",
				}
			},
		},
		{
			Name:     checkSandbox,
			Category: "Security",
			Run: func() doctor.CheckResult {
				sb, err := platform.NewSandbox()
				available := err == nil && sb != nil && sb.IsAvailable()
				if !cfg.Config.Sandbox.Enabled {
					return doctor.CheckResult{
						Status:  doctor.StatusWarn,
						Message: "Sandbox is disabled",
					}
				}
				if !available {
					return doctor.CheckResult{
						Status:  doctor.StatusFail,
						Message: "Sandbox enabled but no driver available on this platform",
					}
				}
				return doctor.CheckResult{
					Status:  doctor.StatusPass,
					Message: fmt.Sprintf("Sandbox enabled (%s)", sb.Name()),
				}
			},
		},
		{
			Name:     checkCA,
			Category: "Security",
			Run: func() doctor.CheckResult {
				user, system, _ := truststore.Status(certmanager.CACommonName)
				return evaluateCACheck(cfg.ConfigDir(), user, system, truststore.UserScopeSupported())
			},
		},
	}

	// System-only: the binary every user's shim execs must stay root-owned and
	// non-writable. Validation runs at install; re-check it here to catch later
	// permission/ownership drift (redeploy, chmod, image rebuild).
	if shim.SystemShimsInstalled() {
		checks = append(checks, doctor.Check{
			Name:     checkSystemBinary,
			Category: "Security",
			Run:      checkSystemBinaryResult,
		})
	}

	return doctor.RunChecks(checks)
}

func checkSystemBinaryResult() doctor.CheckResult {
	path, ok := shim.SystemShimBinary()
	if !ok {
		return doctor.CheckResult{
			Status:  doctor.StatusWarn,
			Message: "Could not determine system shim binary",
		}
	}
	if err := shim.ValidateSystemBinary(path); err != nil {
		return doctor.CheckResult{
			Status:  doctor.StatusFail,
			Message: fmt.Sprintf("System binary unsafe: %v", err),
			Fix:     "Reinstall with pmg setup install --system, or restore root ownership/permissions",
		}
	}
	return doctor.CheckResult{
		Status:  doctor.StatusPass,
		Message: fmt.Sprintf("System binary is root-owned and safe (%s)", path),
	}
}

// checkEventLogDirResult is the testable core of the event-log dir check.
// Event logging is mandatory (init failure is fatal), so an unwritable dir
// fail-closes every pmg command for this user. The remedy is triaged: chown
// when another account created files in this user's home, an environment fix
// when a leaked HOME/XDG_CONFIG_HOME points at another user's home.
func checkEventLogDirResult(skipEventLogging bool, logDir, configDir string) doctor.CheckResult {
	if skipEventLogging {
		return doctor.CheckResult{
			Status:  doctor.StatusWarn,
			Message: "Event logging is disabled",
		}
	}
	info, err := os.Stat(logDir)
	if err != nil {
		return doctor.CheckResult{
			Status:  doctor.StatusFail,
			Message: "Event log directory not found",
		}
	}
	if !info.IsDir() {
		return doctor.CheckResult{
			Status:  doctor.StatusFail,
			Message: "Event log path is not a directory",
		}
	}

	probe, err := os.CreateTemp(logDir, ".pmg-doctor-*")
	if err != nil {
		_, fix := config.UnwritableConfigDirRemedy(configDir)
		return doctor.CheckResult{
			Status:  doctor.StatusFail,
			Message: "Event log directory not writable",
			Fix:     fix,
		}
	}
	if err := probe.Close(); err != nil {
		log.Warnf("failed to close doctor probe file: %v", err)
	}
	if err := os.Remove(probe.Name()); err != nil {
		log.Warnf("failed to remove doctor probe file: %v", err)
	}

	return doctor.CheckResult{
		Status:  doctor.StatusPass,
		Message: "Event log directory found",
	}
}

func pathContainsDir(pathEntries []string, dir string) bool {
	if dir == "" {
		return false
	}
	cleanDir := filepath.Clean(dir)
	for _, entry := range pathEntries {
		if filepath.Clean(entry) == cleanDir {
			return true
		}
	}
	return false
}

// classifyPackageManagerResolutions splits package managers by where they
// resolve on PATH: underShim means the command runs through a pmg shim (so it
// is intercepted), shadowed means a real npm/pip sits ahead of the shims (so
// interception is bypassed and the user should be warned).
func classifyPackageManagerResolutions(packageManagers []string, shimDirs []string, lookPath func(string) (string, error)) (underShim, shadowed []string) {
	for _, pm := range packageManagers {
		resolved, err := lookPath(pm)
		if err != nil {
			continue
		}

		if resolvesUnderAny(resolved, shimDirs) {
			underShim = append(underShim, pm)
			continue
		}
		shadowed = append(shadowed, pm)
	}
	return underShim, shadowed
}

func resolvesUnderAny(path string, dirs []string) bool {
	for _, dir := range dirs {
		if fsutil.PathWithinDir(path, dir) {
			return true
		}
	}
	return false
}

// shimDirs lists every directory a package manager may legitimately resolve
// into. System and per-user installs are supported side by side, so resolution
// into either shim directory counts as intercepted rather than shadowed.
func shimDirs() []string {
	dirs := []string{shim.SystemBinDir()}
	if userDir, err := shim.UserBinDir(); err == nil {
		dirs = append(dirs, userDir)
	}
	return dirs
}

// checkShimDirResolution classifies interception against all shim dirs via
// shimDirs(); shimDir/pathLabel only select the PATH-membership fallback and
// the display label, not which directories count as intercepting.
func checkShimDirResolution(shimDir, pathLabel string, pathEntries []string) doctor.CheckResult {
	underShim, shadowed := classifyPackageManagerResolutions(
		alias.DefaultConfig().PackageManagers,
		shimDirs(),
		exec.LookPath,
	)

	if len(shadowed) > 0 {
		if pathContainsDir(pathEntries, shimDir) || len(underShim) > 0 {
			return doctor.CheckResult{
				Status:  doctor.StatusWarn,
				Message: fmt.Sprintf("%s resolved outside %s", strings.Join(shadowed, ", "), pathLabel),
			}
		}
		return doctor.CheckResult{
			Status:  doctor.StatusFail,
			Message: fmt.Sprintf("%s not in PATH", pathLabel),
		}
	}
	if len(underShim) > 0 {
		return doctor.CheckResult{
			Status:              doctor.StatusPass,
			Message:             fmt.Sprintf("Package managers resolve to %s", pathLabel),
			ImpliesInterception: true,
		}
	}
	if pathContainsDir(pathEntries, shimDir) {
		return doctor.CheckResult{
			Status:              doctor.StatusPass,
			Message:             fmt.Sprintf("%s is in PATH", pathLabel),
			ImpliesInterception: true,
		}
	}
	return doctor.CheckResult{
		Status:  doctor.StatusFail,
		Message: fmt.Sprintf("%s not in PATH", pathLabel),
	}
}

func checkShimInPathResult() doctor.CheckResult {
	pathEntries := filepath.SplitList(os.Getenv("PATH"))

	// The primary directory only picks the label and PATH-membership target;
	// classification accepts resolution into either shim dir regardless.
	shimDir, pathLabel := shim.SystemBinDir(), "System shim directory"
	if !shim.SystemShimsInstalled() {
		userDir, err := shim.UserBinDir()
		if err != nil {
			return doctor.CheckResult{
				Status:  doctor.StatusWarn,
				Message: fmt.Sprintf("Could not resolve shim directory: %v", err),
			}
		}
		shimDir, pathLabel = userDir, "Shim directory"
	}

	return checkShimDirResolution(shimDir, pathLabel, pathEntries)
}

func runProtectionChecks(coreResults []doctor.CheckResult) []doctor.CheckResult {
	if !isInterceptionActive(coreResults) {
		var results []doctor.CheckResult
		for _, tc := range doctor.ProtectionTestCases() {
			results = append(results, doctor.CheckResult{
				Name:     fmt.Sprintf("protection-%s", tc.PackageManager),
				Category: "Protection",
				Status:   doctor.StatusFail,
				Message:  "Aliases and shims not active",
			})
		}
		return results
	}

	pmgBinary, err := os.Executable()
	if err != nil {
		pmgBinary = "pmg"
	}

	var results []doctor.CheckResult
	for _, tc := range doctor.ProtectionTestCases() {
		result := doctor.RunProtectionCheck(tc, pmgBinary)
		result.Category = "Protection"
		result.Name = fmt.Sprintf("protection-%s", tc.PackageManager)
		results = append(results, result)
	}
	return results
}

func isInterceptionActive(coreResults []doctor.CheckResult) bool {
	for _, r := range coreResults {
		if r.ImpliesInterception {
			return true
		}
	}
	return false
}

var checkDisplayNames = map[string]string{
	checkConfigFile:         "Config file",
	checkEventLogDir:        "Event log directory",
	checkShellAliases:       "Shell aliases",
	checkShimDirectory:      "Shim directory",
	checkShimInPath:         "Shim in PATH",
	checkProxyMode:          "Proxy mode",
	checkDependencyCooldown: "Dependency cooldown",
	checkEventLogging:       "Event logging",
	checkSandbox:            "Sandbox",
	checkProtectionNpm:      "npm protection",
	checkProtectionPip:      "pip protection",
	checkCA:                 "MITM CA",
	checkSystemBinary:       "System binary",
}

var checkFixes = map[string]string{
	checkConfigFile:         "pmg setup install",
	checkEventLogDir:        "pmg setup install",
	checkShellAliases:       "pmg setup install",
	checkShimDirectory:      "pmg setup install",
	checkShimInPath:         "Restart shell or source profile",
	checkProxyMode:          "Set proxy.enabled: true in config",
	checkSandbox:            "Set sandbox.enabled: true in config",
	checkDependencyCooldown: "Set dependency_cooldown.enabled: true in config",
	checkEventLogging:       "Set skip_event_logging: false in config",
	checkProtectionNpm:      "pmg setup install",
	checkProtectionPip:      "pmg setup install",
	checkCA:                 "pmg setup cert install",
}

// evaluateCACheck is the testable core of the CA doctor check. Trust booleans
// and userScopeSupported are injected so the check is hermetic; the live check
// fills them from truststore.
func evaluateCACheck(dir string, userTrusted, systemTrusted, userScopeSupported bool) doctor.CheckResult {
	st, err := certmanager.InspectCA(dir)
	if err != nil {
		return doctor.CheckResult{Status: doctor.StatusFail, Message: "CA files present but unreadable"}
	}

	if !st.KeyPresent && !st.CertPresent {
		return doctor.CheckResult{Status: doctor.StatusWarn, Message: "MITM CA not installed (optional; run pmg setup cert install)"}
	}

	st.UserTrusted, st.SystemTrusted = userTrusted, systemTrusted

	if drift, reason := st.Drift(); drift {
		return doctor.CheckResult{Status: doctor.StatusFail, Message: reason}
	}

	if st.Trusted() {
		if st.ExpiringSoon {
			return doctor.CheckResult{Status: doctor.StatusWarn, Message: "CA trusted but expiring within 30 days"}
		}
		return doctor.CheckResult{Status: doctor.StatusPass, Message: "MITM CA installed and trusted"}
	}

	// On disk but not trusted in any store.
	if !userScopeSupported {
		// Linux: env-var injection (SSL_CERT_FILE) already covers Go; store trust optional.
		return doctor.CheckResult{Status: doctor.StatusWarn, Message: "CA on disk; not in OS store (Linux uses SSL_CERT_FILE; --system for store trust)"}
	}
	return doctor.CheckResult{Status: doctor.StatusFail, Message: "CA on disk but not trusted; run pmg setup cert install"}
}

func printResults(results []doctor.CheckResult) {
	fmt.Println()
	fmt.Println(ui.Colors.Cyan("Setup Diagnostics"))
	fmt.Println(ui.Colors.Normal("--------------------"))

	rows := [][]string{{
		ui.Colors.Bold("STATUS"),
		ui.Colors.Bold("CHECK"),
		ui.Colors.Bold("SUMMARY"),
		ui.Colors.Bold("FIX"),
	}}
	for _, r := range results {
		fix := ui.Colors.Dim("—")
		if r.Status != doctor.StatusPass {
			fix = fixHint(r.Name)
			if r.Fix != "" {
				fix = r.Fix
			}
		}
		rows = append(rows, []string{
			statusBadge(r.Status),
			displayName(r.Name),
			ui.Truncate(r.Message, 60),
			fix,
		})
	}

	if err := ui.RenderTable(os.Stdout, rows, nil); err != nil {
		fmt.Fprintf(os.Stderr, "render error: %v\n", err)
	}

	fmt.Println()
	printSummaryLine(results)
}

func statusBadge(s doctor.CheckStatus) string {
	switch s {
	case doctor.StatusPass:
		return ui.Colors.Green("OK")
	case doctor.StatusWarn:
		return ui.Colors.Yellow("WARN")
	case doctor.StatusFail:
		return ui.Colors.Red("FAIL")
	default:
		return "?"
	}
}

func displayName(name string) string {
	if dn, ok := checkDisplayNames[name]; ok {
		return dn
	}
	return name
}

func fixHint(name string) string {
	if fix, ok := checkFixes[name]; ok {
		return fix
	}
	return ui.Colors.Dim("—")
}

func printSummaryLine(results []doctor.CheckResult) {
	passCount, warnCount, failCount := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case doctor.StatusPass:
			passCount++
		case doctor.StatusWarn:
			warnCount++
		case doctor.StatusFail:
			failCount++
		}
	}

	summary := fmt.Sprintf("%d passed", passCount)
	if warnCount > 0 {
		summary += fmt.Sprintf(", %d warnings", warnCount)
	}
	if failCount > 0 {
		summary += fmt.Sprintf(", %d failed", failCount)
		fmt.Printf("%s  %s\n", ui.Colors.Red("FAIL"), ui.Colors.Red(summary))
	} else if warnCount > 0 {
		fmt.Printf("%s  %s\n", ui.Colors.Yellow("WARN"), ui.Colors.Yellow(summary))
	} else {
		fmt.Printf("%s  %s\n", ui.Colors.Green("OK"), ui.Colors.Green(summary))
	}
}
