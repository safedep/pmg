package proxy

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/proxystate"
	pmgproxy "github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/proxy/interceptors"
	"github.com/spf13/cobra"
)

func newStartCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the persistent PMG proxy server (runs in foreground)",
		RunE:  runStart,
	}
}

func runStart(_ *cobra.Command, _ []string) error {
	cfg := config.Get()
	statePath := proxystate.StatePath(cfg.ConfigDir())

	if existing, err := proxystate.Read(statePath); err == nil && existing.IsRunning() {
		return fmt.Errorf("proxy already running (pid %d, addr %s) — run 'pmg proxy stop' first", existing.PID, existing.Addr)
	}

	caCertPath := filepath.Join(cfg.ConfigDir(), "proxy-ca.pem")
	caCert, _, err := flows.SetupCACertificate(cfg.ConfigDir(), caCertPath)
	if err != nil {
		return fmt.Errorf("setup CA certificate: %w", err)
	}

	certMgr, err := certmanager.NewCertificateManagerWithCA(caCert, certmanager.DefaultCertManagerConfig())
	if err != nil {
		return fmt.Errorf("create certificate manager: %w", err)
	}

	malysisAnalyzer, err := analyzer.NewMalysisAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
	if err != nil {
		return fmt.Errorf("create analyzer: %w", err)
	}

	cache := interceptors.NewInMemoryAnalysisCache()
	stats := interceptors.NewAnalysisStatsCollector()
	confirmationChan := make(chan *interceptors.ConfirmationRequest, 100)
	go autoBlockConfirmations(confirmationChan)

	factory := interceptors.NewInterceptorFactory(
		malysisAnalyzer, cache, stats, confirmationChan, interceptors.InterceptorContext{},
	)

	var interceptorList []pmgproxy.Interceptor
	for _, eco := range interceptors.SupportedEcosystems() {
		i, ferr := factory.CreateInterceptor(eco)
		if ferr != nil {
			return fmt.Errorf("create interceptor for %s: %w", eco.String(), ferr)
		}
		interceptorList = append(interceptorList, i)
	}
	interceptorList = append(interceptorList, interceptors.NewAuditLoggerInterceptor())

	proxyConfig := pmgproxy.DefaultProxyConfig()
	proxyConfig.CertManager = certMgr
	proxyConfig.Interceptors = interceptorList

	server, err := pmgproxy.NewProxyServer(proxyConfig)
	if err != nil {
		return fmt.Errorf("create proxy server: %w", err)
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("start proxy server: %w", err)
	}

	state := proxystate.State{
		PID:        os.Getpid(),
		Addr:       server.Address(),
		CACertPath: caCertPath,
	}
	if err := proxystate.Write(statePath, state); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Stop(stopCtx)
		return fmt.Errorf("write proxy state: %w", err)
	}

	log.Infof("PMG persistent proxy running on %s (pid %d)", state.Addr, state.PID)
	if _, err := fmt.Fprintf(os.Stderr, "PMG proxy running on %s\nRun: eval $(pmg proxy env)  # or: pmg proxy env --gha\n", state.Addr); err != nil {
		log.Warnf("failed to write startup message: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	close(confirmationChan)
	_ = proxystate.Remove(statePath)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Stop(stopCtx)
}

// autoBlockConfirmations drains the confirmation channel and always denies,
// appropriate for non-interactive CI/CD environments.
func autoBlockConfirmations(ch chan *interceptors.ConfirmationRequest) {
	for req := range ch {
		log.Warnf("Persistent proxy: auto-blocking suspicious package %s", req.PackageVersion.GetPackage().GetName())
		req.ResponseChan <- false
		close(req.ResponseChan)
	}
}
