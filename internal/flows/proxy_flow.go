package flows

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/guard"
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
func (f *proxyFlow) Run(ctx context.Context, args []string, parsedCmd *packagemanager.ParsedCommand) error {
	cfg := config.Get()

	// Check if dry-run mode is enabled
	if cfg.DryRun {
		ui.SetStatus("Running in dry-run mode (proxy mode)")
		log.Infof("Dry-run mode: Would execute %s with experimental proxy protection", f.pm.Name())
		log.Infof("Dry-run mode: Command would be: %s %v", parsedCmd.Command.Exe, parsedCmd.Command.Args)
		ui.ClearStatus()
		return nil
	}

	ui.SetStatus("Initializing experimental proxy mode...")

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

	// Create analysis cache
	cache := interceptors.NewInMemoryAnalysisCache()

	// Create confirmation channel and start confirmation handler
	confirmationChan := make(chan *interceptors.ConfirmationRequest, 10)
	defer close(confirmationChan)

	// Create interaction callbacks for user prompts
	interaction := guard.PackageManagerGuardInteraction{
		SetStatus:                ui.SetStatus,
		ClearStatus:              ui.ClearStatus,
		ShowWarning:              ui.ShowWarning,
		GetConfirmationOnMalware: ui.GetConfirmationOnMalware,
		Block:                    ui.Block,
	}

	// Get the ecosystem from the package manager
	ecosystem := f.pm.Ecosystem()

	// Check if proxy mode is supported for this ecosystem
	if !interceptors.IsSupported(ecosystem) {
		return fmt.Errorf("proxy mode is not supported for %s", ecosystem.String())
	}

	// Create ecosystem-specific interceptor using factory
	factory := interceptors.NewInterceptorFactory(malysisAnalyzer, cache, confirmationChan, interaction)
	interceptor, err := factory.CreateInterceptor(ecosystem)
	if err != nil {
		return fmt.Errorf("failed to create interceptor for %s: %w", ecosystem.String(), err)
	}

	log.Debugf("Created %s interceptor for ecosystem %s", interceptor.Name(), ecosystem.String())

	// Create and start proxy server
	proxyServer, proxyAddr, err := f.createAndStartProxyServer(certMgr, interceptor)
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

	// Execute the package manager command with proxy environment variables
	return f.executeWithProxy(ctx, parsedCmd, proxyAddr, caCertPath, confirmationChan, interaction)
}

// setupCACertificate generates or loads a CA certificate for MITM
func (f *proxyFlow) setupCACertificate() (*certmanager.Certificate, string, error) {
	log.Debugf("Generating CA certificate for proxy MITM")

	// Generate CA certificate
	caConfig := certmanager.DefaultCertManagerConfig()
	caCert, err := certmanager.GenerateCA(caConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate CA certificate: %w", err)
	}

	// Write CA certificate to temporary file for package managers to trust
	tempDir := os.TempDir()
	caCertPath := filepath.Join(tempDir, fmt.Sprintf("pmg-ca-cert-%d.pem", os.Getpid()))

	if err := os.WriteFile(caCertPath, caCert.Certificate, 0600); err != nil {
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
	cfg := config.Get()

	// Use paranoid mode (active scan) if enabled, otherwise use query mode
	if cfg.Config.Paranoid {
		log.Debugf("Creating malysis active scan analyzer (paranoid mode)")
		return analyzer.NewMalysisActiveScanAnalyzer(analyzer.DefaultMalysisActiveScanAnalyzerConfig())
	}

	log.Debugf("Creating malysis query analyzer")
	return analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
}

// createAndStartProxyServer creates and starts the proxy server with the given interceptor
func (f *proxyFlow) createAndStartProxyServer(
	certMgr certmanager.CertificateManager,
	interceptor proxy.Interceptor,
) (proxy.ProxyServer, string, error) {
	proxyConfig := &proxy.ProxyConfig{
		ListenAddr:     "127.0.0.1:0",
		CertManager:    certMgr,
		EnableMITM:     true,
		Interceptors:   []proxy.Interceptor{interceptor},
		ConnectTimeout: 30 * time.Second,
		RequestTimeout: 5 * time.Minute,
	}

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

// executeWithProxy executes the package manager command with proxy environment variables
func (f *proxyFlow) executeWithProxy(ctx context.Context, parsedCmd *packagemanager.ParsedCommand,
	proxyAddr, caCertPath string, confirmationChan chan *interceptors.ConfirmationRequest,
	interaction guard.PackageManagerGuardInteraction,
) error {
	// Build proxy URL
	proxyURL := fmt.Sprintf("http://%s", proxyAddr)

	// Create command
	cmd := exec.CommandContext(ctx, parsedCmd.Command.Exe, parsedCmd.Command.Args...)

	// Set proxy environment variables
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", caCertPath),
		fmt.Sprintf("http_proxy=%s", proxyURL),
		fmt.Sprintf("https_proxy=%s", proxyURL),
		fmt.Sprintf("NPM_CONFIG_PROGRESS=%t", false),
	)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Debugf("Executing command: %s %v", parsedCmd.Command.Exe, parsedCmd.Command.Args)
	log.Debugf("Proxy environment: HTTP_PROXY=%s, HTTPS_PROXY=%s, NODE_EXTRA_CA_CERTS=%s", proxyURL, proxyURL, caCertPath)

	// Start confirmation handler in goroutine. Use confirmation hooks to pause and resume the executed
	// process to prevent stdout and stderr from being mixed up.
	go interceptors.HandleConfirmationRequests(confirmationChan, interaction, &interceptors.ConfirmationHook{
		BeforeInteraction: func([]*analyzer.PackageVersionAnalysisResult) error {
			if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
				return fmt.Errorf("failed to pause process: %w", err)
			}

			return nil
		},
		AfterInteraction: func([]*analyzer.PackageVersionAnalysisResult, bool) error {
			if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
				return fmt.Errorf("failed to resume process: %w", err)
			}

			return nil
		},
	})

	// Execute the command
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}

		return fmt.Errorf("failed to execute %s: %w", f.pm.Name(), err)
	}

	log.Debugf("Command completed successfully")
	return nil
}
