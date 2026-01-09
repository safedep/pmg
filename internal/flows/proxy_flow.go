package flows

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KennethanCeyer/ptyx"
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
	// Note: We use a pointer so we can later inject the input reader via SetInput
	interaction := &guard.PackageManagerGuardInteraction{
		SetStatus:   ui.SetStatus,
		ClearStatus: ui.ClearStatus,
		ShowWarning: ui.ShowWarning,
		Block:       ui.Block,
	}
	// Set the confirmation handler to use the interaction's reader
	// This allows PTY input routing during proxy mode
	interaction.GetConfirmationOnMalware = func(malwarePackages []*analyzer.PackageVersionAnalysisResult) (bool, error) {
		return ui.GetConfirmationOnMalwareWithReader(malwarePackages, interaction.Reader())
	}

	// Get the ecosystem from the package manager
	ecosystem := f.pm.Ecosystem()

	// Check if proxy mode is supported for this ecosystem
	if !interceptors.IsSupported(ecosystem) {
		return fmt.Errorf("proxy mode is not supported for %s", ecosystem.String())
	}

	// Create ecosystem-specific interceptor using factory
	factory := interceptors.NewInterceptorFactory(malysisAnalyzer, cache, confirmationChan, *interaction)
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

// executeWithProxy executes the package manager command with proxy environment variables.
// This uses the "PTY Switchboard" architecture:
// - Input: Single loop reads os.Stdin and routes to either PTY or Prompt Pipe
// - Output: Thread-safe router switches between Live Pass-through and Buffered modes
// - State: Explicitly toggles between "Cooked" mode (for prompts) and "Raw" mode (for PTY)
func (f *proxyFlow) executeWithProxy(
	ctx context.Context,
	parsedCmd *packagemanager.ParsedCommand,
	proxyAddr, caCertPath string,
	confirmationChan chan *interceptors.ConfirmationRequest,
	interaction *guard.PackageManagerGuardInteraction,
) error {
	proxyURL := fmt.Sprintf("http://%s", proxyAddr)

	// --- 1. Setup Console/TTY ---
	c, err := ptyx.NewConsole()
	if err != nil {
		log.Fatalf("failed to create console: %v", err)
	}
	defer c.Close()

	// Enable virtual terminal processing for color support (especially on Windows)
	c.EnableVT()

	// --- 2. Set Terminal to Raw Mode ---
	// We MUST put the real terminal into Raw mode so we can forward ctrl+c, arrows, etc.
	// We save 'oldState' so we can restore it for prompts and on exit.
	oldState, err := c.MakeRaw()
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %w", err)
	}
	// Safety net: Restore terminal if we crash or exit
	defer func() { _ = c.Restore(oldState) }()

	// --- 3. Get Terminal Size & Spawn PTY ---
	w, h := c.Size()

	s, err := ptyx.Spawn(context.Background(), ptyx.SpawnOpts{
		Prog: parsedCmd.Command.Exe,
		Args: parsedCmd.Command.Args,
		Cols: w,
		Rows: h,
		Env: append(os.Environ(),
			fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
			fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
			fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", caCertPath),
			fmt.Sprintf("http_proxy=%s", proxyURL),
			fmt.Sprintf("https_proxy=%s", proxyURL),
			fmt.Sprintf("SSL_CERT_FILE=%s", caCertPath),
			fmt.Sprintf("REQUESTS_CA_BUNDLE=%s", caCertPath),
			fmt.Sprintf("PIP_CERT=%s", caCertPath),
			fmt.Sprintf("PIP_PROXY=%s", proxyURL),
		),
	})
	if err != nil {
		log.Fatalf("failed to spawn: %v", err)
	}
	defer s.Close()

	// --- 4. Setup The "Switchboards" ---

	// OUTPUT ROUTER: Handles Live vs Buffered output
	router := NewOutputRouter(os.Stdout)
	go func() {
		_, _ = io.Copy(router, s.PtyReader())
	}()

	// INPUT ROUTER: Uses io.Pipe to route input to either PTY or Prompt
	// promptReader -> acts as 'stdin' for the confirmation prompt
	// promptWriter -> where we send keystrokes during a prompt
	promptReader, promptWriter := io.Pipe()
	defer promptWriter.Close()

	// inputDest holds the current destination for keystrokes.
	// If nil -> Send to PTY (normal operation)
	// If set -> Send to that Writer (the prompt pipe)
	// Note: We use atomic.Pointer[writerDest] because atomic.Value panics on nil stores.
	var inputDest atomic.Pointer[writerDest]

	// MAIN INPUT LOOP (The only goroutine reading os.Stdin)
	// This solves the "Input Race" bug - we never stop reading stdin,
	// we just switch where the data goes.
	go func() {
		buf := make([]byte, 1024)
		for {
			nr, err := os.Stdin.Read(buf)
			if err != nil {
				return // Exit on EOF or error
			}

			// Check where to route the data
			if dest := inputDest.Load(); dest != nil {
				// We are prompting! Send keys to the pipe.
				_, _ = dest.w.Write(buf[:nr])
			} else {
				// Normal operation! Send keys to the child PTY.
				_, _ = s.PtyWriter().Write(buf[:nr])
			}
		}
	}()

	// --- 5. Wire up the Confirmation Hooks ---
	go interceptors.HandleConfirmationRequests(
		confirmationChan,
		*interaction,
		&interceptors.ConfirmationHook{
			BeforeInteraction: func(_ []*analyzer.PackageVersionAnalysisResult) error {
				// A. Stop printing child output (Buffer it)
				router.Pause()

				// B. Restore "Cooked" mode so user can type normally with echo
				_ = c.Restore(oldState)

				// C. Force cursor visible (ANSI escape sequence)
				fmt.Fprint(os.Stdout, "\033[?25h")

				// D. Switch Input: Route keystrokes to the Prompt Pipe
				inputDest.Store(&writerDest{w: promptWriter})

				// E. Inject the Reader into the Interaction for the confirmation prompt
				interaction.SetInput(promptReader)

				return nil
			},
			AfterInteraction: func(_ []*analyzer.PackageVersionAnalysisResult, _ bool) error {
				// A. Switch Input: Route keystrokes back to PTY (nil means PTY)
				inputDest.Store(nil)

				// B. Restore "Raw" mode for the child PTY
				_, _ = c.MakeRaw()

				// C. Clear the interaction input (back to default)
				interaction.SetInput(nil)

				// D. Flush buffered output and resume live output
				router.Resume()

				return nil
			},
		},
	)

	// --- 6. Wait for Child Process ---
	err = s.Wait()
	if err != nil {
		if exitErr, ok := err.(*ptyx.ExitError); ok {
			// IMPORTANT: Restore terminal BEFORE os.Exit() because
			// os.Exit() does NOT run deferred functions!
			// If we don't restore, the terminal is left in raw mode
			// and subsequent runs will be corrupted.
			_ = c.Restore(oldState)
			promptWriter.Close()
			os.Exit(exitErr.ExitCode)
		}
		return err
	}

	return nil
}

// writerDest wraps an io.Writer for use with atomic.Pointer.
// This is needed because atomic.Value panics when storing nil interface values,
// but atomic.Pointer allows nil pointer stores.
type writerDest struct {
	w io.Writer
}

// OutputRouter manages the stdout stream. It can pause "Live" output
// and buffer it in memory, then flush it later. This prevents the child
// process's spinner/progress output from corrupting the confirmation prompt.
type OutputRouter struct {
	mu        sync.Mutex
	out       io.Writer    // The real destination (os.Stdout)
	buffer    bytes.Buffer // Temporary storage during prompts
	buffering bool         // The mode flag
}

func NewOutputRouter(out io.Writer) *OutputRouter {
	return &OutputRouter{
		out: out,
	}
}

// Write implements io.Writer. It is thread-safe.
func (r *OutputRouter) Write(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.buffering {
		// We are in "Prompt Mode", so save this output for later.
		// If we printed it now, it would mess up the "Allow [y/N]?" prompt.
		return r.buffer.Write(p)
	}

	// Normal mode: just print it to stdout.
	return r.out.Write(p)
}

// Pause starts buffering output. Call this before showing a confirmation prompt.
func (r *OutputRouter) Pause() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buffering = true
}

// Resume stops buffering, flushes any buffered output, and resumes live output.
// Call this after the confirmation prompt is complete.
func (r *OutputRouter) Resume() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Flush any buffered output
	if r.buffer.Len() > 0 {
		_, _ = io.Copy(r.out, &r.buffer)
		r.buffer.Reset()
	}

	r.buffering = false
}

// SetBuffering sets the buffering state directly.
func (r *OutputRouter) SetBuffering(enable bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buffering = enable
}

// Flush prints everything that was hidden while buffering was on.
func (r *OutputRouter) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.buffer.Len() > 0 {
		// Write the stored logs to the real output
		_, _ = io.Copy(r.out, &r.buffer)
		r.buffer.Reset()
	}
}
