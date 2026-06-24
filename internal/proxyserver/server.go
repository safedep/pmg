package proxyserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/safedep/dry/localdb"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/analyzer/malysiscache"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/flows"
	pmgproxy "github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/proxy/interceptors"
)

const (
	serverStopTimeout     = 5 * time.Second
	cloudFlushLockTimeout = 30 * time.Second
	cloudFlushTimeout     = 2 * time.Minute

	// daemonShutdownBudget is the worst-case time the daemon needs to shut down
	// (drain in-flight requests, then flush to cloud). `pmg proxy stop` waits at
	// least this long for the daemon to exit; see stopWaitTimeout.
	daemonShutdownBudget = serverStopTimeout + cloudFlushLockTimeout + cloudFlushTimeout
)

type ProxyDaemonConfig struct {
	LogPath  string
	CacheDir string
}

// Run starts the persistent proxy server in the foreground and blocks until it
// receives SIGINT/SIGTERM. It writes the state file on startup, auto-blocks
// suspicious packages, and records the final blocked count on shutdown.
func Run(ctx context.Context, cfg *config.RuntimeConfig, statePath string, port int) error {
	if existing, err := readState(statePath); err == nil && existing.IsRunning() {
		return fmt.Errorf("proxy already running (pid %d, addr %s) — run 'pmg proxy stop' first", existing.PID, existing.Addr)
	}

	caCertPath := certmanager.ProxyCABundlePath(cfg.ConfigDir())
	caCert, _, err := flows.SetupCACertificate(cfg.ConfigDir(), caCertPath)
	if err != nil {
		return fmt.Errorf("setup CA certificate: %w", err)
	}

	certMgr, err := certmanager.NewCertificateManagerWithCA(caCert, certmanager.DefaultCertManagerConfig())
	if err != nil {
		return fmt.Errorf("create certificate manager: %w", err)
	}

	malysisAnalyzer, closeAnalyzer, err := buildAnalyzer(ctx, cfg)
	if err != nil {
		return fmt.Errorf("create analyzer: %w", err)
	}
	defer func() {
		if cerr := closeAnalyzer(); cerr != nil {
			log.Warnf("failed to close analyzer cache: %v", cerr)
		}
	}()

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
	proxyConfig.ListenAddr = listenAddr(cfg, port)
	proxyConfig.CertManager = certMgr
	proxyConfig.Interceptors = interceptorList

	server, err := pmgproxy.NewProxyServer(proxyConfig)
	if err != nil {
		return fmt.Errorf("create proxy server: %w", err)
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("start proxy server: %w", err)
	}

	state := State{
		PID:        os.Getpid(),
		Addr:       server.Address(),
		CACertPath: caCertPath,
	}
	if err := writeState(statePath, state); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), serverStopTimeout)
		defer cancel()
		if serr := server.Stop(stopCtx); serr != nil {
			log.Warnf("failed to stop proxy after state write failure: %v", serr)
		}
		return fmt.Errorf("write proxy state: %w", err)
	}

	log.Infof("PMG persistent proxy running on %s (pid %d)", state.Addr, state.PID)
	if _, err := fmt.Fprintf(os.Stderr, "PMG proxy running on %s\nRun: export $(pmg proxy env | xargs)  # or: pmg proxy env >> \"$GITHUB_ENV\"\n", state.Addr); err != nil {
		log.Warnf("failed to write startup message: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	// Drain in-flight requests before closing the confirmation channel, so no
	// request handler can send on a closed channel (panic) during shutdown.
	stopCtx, cancel := context.WithTimeout(context.Background(), serverStopTimeout)
	defer cancel()
	stopErr := server.Stop(stopCtx)

	close(confirmationChan)

	// Count is read after drain so a package analyzed at shutdown is not missed.
	// Persist it BEFORE the (possibly slow) cloud flush so the blocked count
	// survives even if the flush hangs or the daemon is killed mid-flush, which
	// keeps `stop --fail-on-violation` correct in those cases.
	state.BlockedCount = stats.GetStats().BlockedCount
	if werr := writeState(statePath, state); werr != nil {
		log.Warnf("failed to write final proxy state: %v", werr)
	}

	// Flush audit events to SafeDep Cloud from the daemon. Unlike `pmg proxy
	// stop`, the daemon has no proxy env vars (it started before `pmg proxy env`
	// injected them), so its cloud client dials SafeDep directly instead of
	// routing through the proxy that is now shutting down. The result is
	// recorded in the state file so `stop` can report it (the daemon's own logs
	// are not visible to the stop process). Uses a fresh context because the
	// caller's may already be cancelled at shutdown.
	if cfg.Config.Cloud.Enabled {
		synced, ferr := audit.DrainToCloud(context.Background(), cfg, cloudFlushLockTimeout, cloudFlushTimeout)
		state.CloudSync = &CloudSyncResult{Synced: synced}
		if ferr != nil {
			state.CloudSync.Error = ferr.Error()
			log.Warnf("cloud event flush failed: %v", ferr)
		} else {
			log.Infof("Flushed %d events to SafeDep Cloud", synced)
		}

		if werr := writeState(statePath, state); werr != nil {
			log.Warnf("failed to write final proxy state: %v", werr)
		}
	}

	return stopErr
}

// listenAddr resolves the proxy's bind address from config (host) and the
// --port flag. Host defaults to loopback.
func listenAddr(cfg *config.RuntimeConfig, port int) string {
	host := cfg.Config.Proxy.Server.ListenHost
	if host == "" {
		host = "127.0.0.1"
	}

	return net.JoinHostPort(host, strconv.Itoa(port))
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

// buildAnalyzer constructs the malysis analyzer with the persistent analysis
// cache when enabled. The returned closer releases the localdb handle (no-op
// when the cache is disabled or unavailable). Cache failures degrade to an
// uncached analyzer and never abort.
func buildAnalyzer(ctx context.Context, cfg *config.RuntimeConfig) (analyzer.PackageVersionAnalyzer, func() error, error) {
	noop := func() error { return nil }

	var malysisCache analyzer.MalysisCache
	closer := noop

	cacheCfg := cfg.Config.AnalysisCache.Malysis
	if cacheCfg.Enabled && cacheCfg.TTL > 0 {
		mgr := localdb.New(localdb.Config{
			Dir:      cfg.LocalDBDir(),
			FileName: cfg.LocalDBFileName(),
		})
		store, serr := mgr.Store(ctx, malysiscache.Descriptor())
		if serr != nil {
			log.Warnf("analysis cache unavailable, continuing without it: %v", serr)
			if cerr := mgr.Close(); cerr != nil {
				log.Warnf("failed to close localdb: %v", cerr)
			}
		} else {
			malysisCache = malysiscache.New(store, cacheCfg)
			closer = mgr.Close
		}
	}

	a, err := analyzer.NewMalysisAnalyzer(analyzer.MalysisQueryAnalyzerConfig{Cache: malysisCache})
	if err != nil {
		if cerr := closer(); cerr != nil {
			log.Warnf("failed to close localdb: %v", cerr)
		}
		return nil, noop, err
	}

	return a, closer, nil
}
