package flows

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/guard"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/runner"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/proxy/interceptors"
)

type proxyFlow struct {
	pm              packagemanager.PackageManager
	packageResolver packagemanager.PackageResolver
}

// ProxyFlow creates a new proxy-based flow for package manager protection
func ProxyFlow(pm packagemanager.PackageManager, packageResolver packagemanager.PackageResolver) *proxyFlow {
	return &proxyFlow{
		pm:              pm,
		packageResolver: packageResolver,
	}
}

// Run executes the proxy-based flow
func (f *proxyFlow) Run(ctx context.Context, args []string, parsedCmd *packagemanager.ParsedCommand) (runErr error) {
	// Check if we have a supported ecosystem else fail fast
	ecosystem := f.pm.Ecosystem()
	if !interceptors.IsSupported(ecosystem) {
		return fmt.Errorf("proxy mode is not supported for %s", ecosystem.String())
	}

	// Configure sandbox based on command type and enforcement policy
	config.ConfigureSandbox(parsedCmd.IsInstallationCommand() || parsedCmd.MayDownloadPackages())

	cfg := config.Get()

	// When install_only is enabled, skip proxy for known non-download commands
	// and user-defined skip commands
	if cfg.Config.Proxy.InstallOnly {
		if !parsedCmd.MayDownloadPackages() {
			log.Debugf("Skipping proxy for non-download command (install_only=true)")
			return runner.Execute(ctx, parsedCmd, f.pm.Name(), cfg.DryRun)
		}

		if cmds, ok := cfg.Config.Proxy.SkipCommands[f.pm.Name()]; ok && len(cmds) > 0 {
			if packagemanager.IsFirstNonFlagArgInList(parsedCmd.Command.Args, cmds) {
				log.Debugf("Skipping proxy for user-defined skip command (install_only=true)")
				return runner.Execute(ctx, parsedCmd, f.pm.Name(), cfg.DryRun)
			}
		}
	}

	// Initialize report data at the start
	reportData := ui.NewReportData()
	reportData.PackageManagerName = f.pm.Name()
	reportData.FlowType = ui.FlowTypeProxy
	reportData.DryRun = cfg.DryRun
	reportData.InsecureMode = cfg.InsecureInstallation
	reportData.TransitiveEnabled = cfg.Config.Transitive
	reportData.ParanoidMode = cfg.Config.Paranoid
	reportData.SandboxEnabled = cfg.Config.Sandbox.Enabled

	if cfg.Config.Sandbox.Enabled {
		if policyRef, exists := cfg.Config.Sandbox.Policies[f.pm.Name()]; exists {
			reportData.SandboxProfile = policyRef.Profile
		}
	}

	if cfg.SandboxProfileOverride != "" {
		reportData.SandboxProfile = cfg.SandboxProfileOverride
	}

	startTime := time.Now()

	audit.LogInstallStarted(f.pm.Name(), args)

	sessionCompleted := false
	defer func() {
		if sessionCompleted {
			return
		}

		// On early error returns (e.g. CA cert, analyzer init), reportData.Outcome
		// is still the default (Success). Override to Error for these cases.
		if runErr != nil && reportData.Outcome == ui.OutcomeSuccess {
			reportData.Outcome = ui.OutcomeError
		}

		audit.LogSessionComplete(audit.Outcome(reportData.Outcome.String()), audit.FlowTypeProxy)
	}()

	// Check if dry-run mode is enabled
	if cfg.DryRun {
		log.Infof("Dry-run mode: Would execute %s with proxy protection", f.pm.Name())
		log.Infof("Dry-run mode: Command would be: %s %v", parsedCmd.Command.Exe, parsedCmd.Command.Args)

		reportData.Outcome = ui.OutcomeDryRun
		ui.Report(reportData)

		return nil
	}

	// Setup CA certificate for MITM
	caCert, caCertPath, err := f.setupCACertificate()
	if err != nil {
		return fmt.Errorf("failed to setup CA certificate for proxy mode: %w", err)
	}

	defer func() {
		// Clean up temporary CA certificate file
		if caCertPath != "" {
			if err := os.Remove(caCertPath); err != nil {
				log.Errorf("Failed to remove CA certificate file: %v", err)
			}
		}
	}()

	// Create certificate manager
	certMgr, err := f.createCertificateManager(caCert)
	if err != nil {
		return fmt.Errorf("failed to create certificate manager: %w", err)
	}

	// Create analyzer
	malysisAnalyzer, err := f.createAnalyzer()
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %w", err)
	}

	// Create analysis cache and stats collector
	cache := interceptors.NewInMemoryAnalysisCache()
	statsCollector := interceptors.NewAnalysisStatsCollector()

	// Create confirmation channel and start confirmation handler
	confirmationChan := make(chan *interceptors.ConfirmationRequest, 10)
	defer close(confirmationChan)

	// Create interaction callbacks for user prompts
	// Note: We use a pointer so we can later inject the input reader via SetInput
	interaction := &guard.PackageManagerGuardInteraction{
		SetStatus:   ui.SetStatus,
		ClearStatus: ui.ClearStatus,
		ShowWarning: ui.ShowWarning,
		Block:       ui.BlockNoExit,
	}

	// Extract pinned versions from install targets so cooldown handlers can
	// report when a user's explicitly requested version was blocked.
	pinnedVersions := make(map[string]string)
	for _, target := range parsedCmd.InstallTargets {
		if target.IsExplicitVersion {
			pinnedVersions[target.PackageVersion.GetPackage().GetName()] = target.PackageVersion.GetVersion()
		}
	}

	// Create ecosystem-specific interceptor using factory
	factory := interceptors.NewInterceptorFactory(malysisAnalyzer, cache, statsCollector, confirmationChan, interceptors.InterceptorContext{
		PinnedVersions: pinnedVersions,
	})
	interceptor, err := factory.CreateInterceptor(ecosystem)
	if err != nil {
		return fmt.Errorf("failed to create interceptor for %s: %w", ecosystem.String(), err)
	}

	log.Debugf("Created %s interceptor for ecosystem %s", interceptor.Name(), ecosystem.String())

	// Create and start proxy server
	proxyServer, proxyAddr, err := f.createAndStartProxyServer(certMgr, []proxy.Interceptor{
		interceptor,
		interceptors.NewAuditLoggerInterceptor(),
	})
	if err != nil {
		return fmt.Errorf("failed to start proxy server: %w", err)
	}

	// Ensure proxy is stopped on exit
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := proxyServer.Stop(shutdownCtx); err != nil {
			log.Errorf("Failed to stop proxy server: %v", err)
		}
	}()

	ui.ClearStatus()

	log.Infof("Proxy server started on %s", proxyAddr)
	log.Infof("Running %s with proxy protection enabled", f.pm.Name())

	executionError := runner.ExecuteWithOptions(ctx, parsedCmd, runner.ExecuteOptions{
		PackageManagerName: f.pm.Name(),
		DryRun:             cfg.DryRun,
		Mode:               runner.ExecutionModeAuto,
		EnvOverrides:       f.setupEnvForProxy(proxyAddr, caCertPath),
		DirectEnvOverrides: []string{"CI=true"},
		BeforeDirectRun: func() error {
			log.Debugf("Executing proxy for non interactive TTY")

			interaction.GetConfirmationOnMalware = func(_ []*analyzer.PackageVersionAnalysisResult) (bool, error) {
				return false, nil
			}

			go interceptors.HandleConfirmationRequests(confirmationChan, interaction, nil)
			return nil
		},
		PreparePTYSession: func(runtime *runner.PTYRuntime) error {
			log.Debugf("Executing proxy for interactive TTY")

			interaction.GetConfirmationOnMalware = func(malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error) {
				return ui.GetConfirmationOnMalwareWithReader(malwarePackages, interaction.Reader())
			}

			go interceptors.HandleConfirmationRequests(
				confirmationChan,
				interaction,
				&interceptors.ConfirmationHook{
					BeforeInteraction: func(_ []*analyzer.PackageVersionAnalysisResult) error {
						runtime.OutputRouter.Pause()

						if err := runtime.Session.SetCookedMode(); err != nil {
							return fmt.Errorf("failed to set cooked mode: %w", err)
						}

						if _, err := fmt.Fprint(os.Stdout, "\033[?25h"); err != nil {
							log.Warnf("failed to force cursor visible: %v", err)
						}

						runtime.InputRouter.RouteToPrompt(runtime.PromptWriter)
						interaction.SetInput(runtime.PromptReader)

						return nil
					},
					AfterInteraction: func(_ []*analyzer.PackageVersionAnalysisResult, _ bool) error {
						runtime.InputRouter.RouteToPTY()

						if err := runtime.Session.SetRawMode(); err != nil {
							return fmt.Errorf("failed to set raw mode: %w", err)
						}

						interaction.SetInput(nil)
						runtime.OutputRouter.Resume()

						return nil
					},
				},
			)

			return nil
		},
	})

	// Populate report data from stats collector
	stats := statsCollector.GetStats()
	reportData.StartTime = startTime
	reportData.TotalAnalyzed = stats.TotalAnalyzed
	reportData.AllowedCount = stats.AllowedCount
	reportData.ConfirmedCount = stats.ConfirmedCount
	reportData.BlockedCount = stats.BlockedCount
	reportData.BlockedPackages = statsCollector.GetBlockedPackages()
	reportData.ConfirmedPackages = statsCollector.GetConfirmedPackages()
	reportData.CooldownBlockedPackages = statsCollector.GetCooldownBlocks()

	// Set outcome based on execution result using shared inference logic
	reportData.Outcome = inferOutcome(cfg.InsecureInstallation, cfg.DryRun, reportData.BlockedCount, stats.UserCancelledCount, executionError)

	// Emit session complete before report/exit — handleExecutionResultError may call
	// os.Exit which skips defers, so we must emit the session summary here.
	audit.LogSessionComplete(audit.Outcome(reportData.Outcome.String()), audit.FlowTypeProxy)
	sessionCompleted = true

	// Show the report
	ui.Report(reportData)

	// Run should always end with handleExecutionResultError to ensure the process exits with the correct exit code
	// from the execution result.
	return handleExecutionResultError(executionError)
}

// handleExecutionResultError handles the error from the execution result.
func handleExecutionResultError(err error) error {
	if err == nil {
		return nil
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		os.Exit(exitErr.ExitCode())
	}

	return fmt.Errorf("failed to execute command: %w", err)
}

// setupCACertificate generates CA for MITM and writes proxy bundle for child package managers.
func (f *proxyFlow) setupCACertificate() (*certmanager.Certificate, string, error) {
	log.Debugf("Generating CA certificate for proxy MITM")

	// Generate CA certificate
	caConfig := certmanager.DefaultCertManagerConfig()
	caCert, err := certmanager.GenerateCAWithSystemCA(caConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate CA certificate: %w", err)
	}

	// Write CA certificate to temporary file for package managers to trust
	tempDir := os.TempDir()
	caCertPath := filepath.Join(tempDir, fmt.Sprintf("pmg-ca-cert-%d.pem", os.Getpid()))

	if err := os.WriteFile(caCertPath, caCert.Certificate, 0o600); err != nil {
		return nil, "", fmt.Errorf("failed to write CA certificate to %s: %w", caCertPath, err)
	}

	log.Debugf("CA certificate written to %s", caCertPath)

	return caCert, caCertPath, nil
}

// createCertificateManager creates a certificate manager with the given CA certificate
func (f *proxyFlow) createCertificateManager(caCert *certmanager.Certificate) (certmanager.CertificateManager, error) {
	caConfig := certmanager.DefaultCertManagerConfig()
	certMgr, err := certmanager.NewCertificateManagerWithCA(caCert, caConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate manager: %w", err)
	}

	return certMgr, nil
}

// createAnalyzer creates the malysis query analyzer
func (f *proxyFlow) createAnalyzer() (analyzer.PackageVersionAnalyzer, error) {
	log.Debugf("Creating malysis query analyzer")
	return analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
}

// createAndStartProxyServer creates and starts the proxy server with the given interceptor
func (f *proxyFlow) createAndStartProxyServer(
	certMgr certmanager.CertificateManager,
	interceptorsList []proxy.Interceptor,
) (proxy.ProxyServer, string, error) {
	proxyConfig := proxy.DefaultProxyConfig()
	proxyConfig.CertManager = certMgr
	proxyConfig.Interceptors = interceptorsList

	proxyServer, err := proxy.NewProxyServer(proxyConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create proxy server: %w", err)
	}

	if err := proxyServer.Start(); err != nil {
		return nil, "", fmt.Errorf("failed to start proxy server: %w", err)
	}

	proxyAddr := proxyServer.Address()
	if proxyAddr == "" {
		return nil, "", fmt.Errorf("proxy server started but address is empty")
	}

	return proxyServer, proxyAddr, nil
}

func (f *proxyFlow) setupEnvForProxy(proxyAddr, caCertPath string) []string {
	proxyURL := fmt.Sprintf("http://%s", proxyAddr)

	noProxyList := "localhost,127.0.0.1,[::1]"

	return []string{
		"NODE_USE_ENV_PROXY=1",
		fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("NO_PROXY=%s", noProxyList),
		fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", caCertPath),
		fmt.Sprintf("http_proxy=%s", proxyURL),
		fmt.Sprintf("https_proxy=%s", proxyURL),
		fmt.Sprintf("no_proxy=%s", noProxyList),
		fmt.Sprintf("SSL_CERT_FILE=%s", caCertPath),
		fmt.Sprintf("REQUESTS_CA_BUNDLE=%s", caCertPath),
		fmt.Sprintf("PIP_CERT=%s", caCertPath),
		fmt.Sprintf("PIP_PROXY=%s", proxyURL),
		"PIP_RETRIES=0",
	}
}
