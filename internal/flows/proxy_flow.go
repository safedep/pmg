package flows

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/guard"
	"github.com/safedep/pmg/internal/pty"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/proxy/interceptors"
	"github.com/safedep/pmg/sandbox/executor"
	"github.com/safedep/pmg/usefulerror"
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

	// Get the ecosystem from the package manager
	ecosystem := f.pm.Ecosystem()

	// Check if proxy mode is supported for this ecosystem
	if !interceptors.IsSupported(ecosystem) {
		return fmt.Errorf("proxy mode is not supported for %s", ecosystem.String())
	}

	config.ConfigureSandbox(parsedCmd.IsInstallationCommand())

	cfg := config.Get()

	// Check if dry-run mode is enabled
	if cfg.DryRun {
		log.Infof("Dry-run mode: Would execute %s with experimental proxy protection", f.pm.Name())
		log.Infof("Dry-run mode: Command would be: %s %v", parsedCmd.Command.Exe, parsedCmd.Command.Args)

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
	// Note: We use a pointer so we can later inject the input reader via SetInput
	interaction := &guard.PackageManagerGuardInteraction{
		SetStatus:   ui.SetStatus,
		ClearStatus: ui.ClearStatus,
		ShowWarning: ui.ShowWarning,
		Block:       ui.BlockNoExit,
	}

	// Create ecosystem-specific interceptor using factory
	factory := interceptors.NewInterceptorFactory(malysisAnalyzer, cache, confirmationChan)
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

	proxyEnv := f.setupEnvForProxy(proxyAddr, caCertPath)

	var executionError error
	if !pty.IsInteractiveTerminal() {
		// Execute the package manager command with proxy environment variables for non PTY or non-interactive TTY
		executionError = f.executeWithProxyForNonInteractiveTTY(ctx, parsedCmd, proxyEnv, confirmationChan, interaction)
	} else {
		// Execute the package manager command with proxy environment variables
		executionError = f.executeWithProxy(ctx, parsedCmd, proxyEnv, confirmationChan, interaction)
	}

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

func (f *proxyFlow) setupEnvForProxy(proxyAddr, caCertPath string) []string {
	proxyURL := fmt.Sprintf("http://%s", proxyAddr)

	env := os.Environ()
	env = append(env,
		fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", caCertPath),
		fmt.Sprintf("http_proxy=%s", proxyURL),
		fmt.Sprintf("https_proxy=%s", proxyURL),
		fmt.Sprintf("SSL_CERT_FILE=%s", caCertPath),
		fmt.Sprintf("REQUESTS_CA_BUNDLE=%s", caCertPath),
		fmt.Sprintf("PIP_CERT=%s", caCertPath),
		fmt.Sprintf("PIP_PROXY=%s", proxyURL),
	)

	return env
}

// executeWithProxyForNonInteractiveTTY runs the command without PTY (for CI/non-interactive environments)
func (f *proxyFlow) executeWithProxyForNonInteractiveTTY(
	ctx context.Context,
	parsedCmd *packagemanager.ParsedCommand,
	env []string,
	confirmationChan chan *interceptors.ConfirmationRequest,
	interaction *guard.PackageManagerGuardInteraction,
) error {
	log.Debugf("Executing proxy for non interactive TTY")

	// For non-interactive terminals, we enforce suspicious packages as malicious
	interaction.GetConfirmationOnMalware = func(malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error) {
		return false, nil
	}

	cmd := exec.CommandContext(ctx, parsedCmd.Command.Exe, parsedCmd.Command.Args...)
	cmd.Env = append(env, "CI=true")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	go interceptors.HandleConfirmationRequests(
		confirmationChan,
		interaction,
		nil,
	)

	result, err := executor.ApplySandbox(ctx, cmd, f.pm.Name())
	if err != nil {
		return fmt.Errorf("failed to apply sandbox: %w", err)
	}

	defer func() {
		err := result.Close()
		if err != nil {
			log.Errorf("failed to close sandbox: %v", err)
		}
	}()

	// Only run the command if the sandbox didn't already execute it
	if result.ShouldRun() {
		log.Debugf("Running command with args: %s: %v", cmd.Path, cmd.Args[1:])

		err = cmd.Run()
		if err != nil {
			return f.handlePackageManagerExecutionError(err)
		}
	}

	log.Debugf("Command completed successfully")
	return nil
}

// executeWithProxy executes the package manager command with proxy environment variables.
func (f *proxyFlow) executeWithProxy(
	ctx context.Context,
	parsedCmd *packagemanager.ParsedCommand,
	env []string,
	confirmationChan chan *interceptors.ConfirmationRequest,
	interaction *guard.PackageManagerGuardInteraction,
) error {
	log.Debugf("Executing proxy for interactive TTY")

	// Set the confirmation handler to use the interaction's reader
	// This allows PTY input routing during proxy mode
	interaction.GetConfirmationOnMalware = func(malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error) {
		return ui.GetConfirmationOnMalwareWithReader(malwarePackages, interaction.Reader())
	}

	cmd := exec.CommandContext(ctx, parsedCmd.Command.Exe, parsedCmd.Command.Args...)
	result, err := executor.ApplySandbox(ctx, cmd, f.pm.Name())
	if err != nil {
		return fmt.Errorf("failed to apply sandbox: %w", err)
	}

	if !result.ShouldRun() {
		return usefulerror.Useful().
			Wrap(fmt.Errorf("sandbox not supported for PTY sessions")).
			WithHumanError("Sandbox executed command cannot be used with PTY session. Please use non-interactive TTY mode instead.")
	}

	// Extract the command executable and arguments from the sandboxed command
	// for use to create the PTY session.
	cmdExe := cmd.Path
	cmdArgs := cmd.Args[1:]

	log.Debugf("Running command with args: %s: %v", cmdExe, cmdArgs)

	// Create the PTY session with the sandbox command
	// This is not compatible with sandbox that executes the command directly within the sandbox
	// because internally we use ptyx.Spawn() to create the process with PTY support.
	sessionConfig := pty.NewSessionConfig(cmdExe, cmdArgs, env)

	sess, err := pty.NewSession(ctx, sessionConfig)
	if err != nil {
		return fmt.Errorf("failed to create pty session: %w", err)
	}
	defer sess.Close()

	outputRouter, err := pty.NewOutputRouter(os.Stdout)
	if err != nil {
		return fmt.Errorf("failed to create output router: %w", err)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		if _, err := io.Copy(outputRouter, sess.PtyReader()); err != nil {
			log.Errorf("failed to copy output: %v", err)
		}
	})

	inputRouter, err := pty.NewInputRouter(sess.PtyWriter())
	if err != nil {
		return fmt.Errorf("failed to create input router: %w", err)
	}

	promptReader, promptWriter := io.Pipe()
	defer func() {
		promptWriter.Close()
		promptReader.Close()
	}()

	// Note: This goroutine cannot be cleanly cancelled because os.Stdin.Read() is
	// a blocking syscall that doesn't support timeouts or cancellation. This is a
	// known limitation. The goroutine will exit when the process terminates, which
	// is acceptable for a CLI tool. For long-running servers, stdin reading should
	// be handled differently.
	go inputRouter.ReadLoop(os.Stdin)

	go interceptors.HandleConfirmationRequests(
		confirmationChan,
		interaction,
		&interceptors.ConfirmationHook{
			BeforeInteraction: func(_ []*analyzer.PackageVersionAnalysisResult) error {
				// Pause printing the child output
				outputRouter.Pause()

				// Restore "Cooked" mode so user can type normally with echo
				if err := sess.SetCookedMode(); err != nil {
					return fmt.Errorf("failed to set cooked mode: %w", err)
				}

				// Force cursor visible (ANSI escape sequence)
				fmt.Fprint(os.Stdout, "\033[?25h")

				// Switch Input: Route keystrokes to the Prompt Pipe
				inputRouter.RouteToPrompt(promptWriter)

				// Inject the Reader into the Interaction for the confirmation prompt
				interaction.SetInput(promptReader)

				return nil
			},
			AfterInteraction: func(_ []*analyzer.PackageVersionAnalysisResult, _ bool) error {
				// Switch input back to PTY
				inputRouter.RouteToPTY()

				// Restore "Raw" mode for the PTY
				if err := sess.SetRawMode(); err != nil {
					return fmt.Errorf("failed to set raw mode: %w", err)
				}

				// Clear the interaction input (back to default)
				interaction.SetInput(nil)

				// Flush buffered output and resume live output
				outputRouter.Resume()

				return nil
			},
		},
	)

	// sessionError may contain the exit code of the command if the command exited with a non-zero code.
	sessionError := sess.Wait()

	// Wait for the routers to copy all the remaining data
	wg.Wait()

	if err := promptReader.Close(); err != nil {
		log.Errorf("failed to close prompt reader: %v", err)
	}

	if err := promptWriter.Close(); err != nil {
		log.Errorf("failed to close prompt writer: %v", err)
	}

	if err := sess.Close(); err != nil {
		log.Errorf("failed to close session: %v", err)
	}

	if sessionError != nil {
		return f.handlePackageManagerExecutionError(sessionError)
	}

	return nil
}

func (f *proxyFlow) handlePackageManagerExecutionError(err error) error {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return usefulerror.Useful().
			WithCode(usefulerror.ErrCodePackageManagerExecutionFailed).
			WithHumanError(fmt.Sprintf("Package manager command exited with code: %d", exitErr.ExitCode())).
			WithHelp("Check the package manager command and its arguments").
			Wrap(err)
	}

	if sessionError, ok := err.(*pty.ExitError); ok {
		return usefulerror.Useful().
			WithCode(usefulerror.ErrCodePackageManagerExecutionFailed).
			WithHumanError(fmt.Sprintf("Package manager command exited with code: %d", sessionError.Code)).
			WithHelp("Check the package manager command and its arguments").
			Wrap(sessionError.Err)
	}

	return usefulerror.Useful().
		WithCode(usefulerror.ErrCodePackageManagerExecutionFailed).
		WithHumanError("Failed to execute package manager command").
		WithHelp("Check the package manager command and its arguments").
		Wrap(err)
}
