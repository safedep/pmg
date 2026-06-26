package proxyserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/localstore"
	pmgproxy "github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/proxy/interceptors"
)

const (
	serverStopTimeout = 5 * time.Second

	// Periodic cloud sync runs while the daemon is alive so most audit events are
	// delivered during the run and the shutdown flush stays small. A tick that
	// cannot get the sync lock quickly is skipped (the next tick retries).
	cloudSyncInterval     = 15 * time.Second
	cloudSyncTickLockWait = 5 * time.Second
	cloudSyncTickTimeout  = 30 * time.Second

	// Final flush at shutdown, when the daemon drains whatever the ticker left.
	cloudFlushLockWait = 30 * time.Second
	cloudFlushTimeout  = 2 * time.Minute

	// daemonShutdownBudget is the worst-case time the daemon needs to shut down:
	// drain in-flight requests, wait for an in-flight periodic tick to finish,
	// then the final flush. `pmg proxy stop` waits at least this long for the
	// daemon to exit; see stopWaitTimeout.
	daemonShutdownBudget = serverStopTimeout +
		cloudSyncTickLockWait + cloudSyncTickTimeout +
		cloudFlushLockWait + cloudFlushTimeout
)

// DefaultDaemonReadyTimeout is how long the parent waits for the daemon to
// become ready before giving up, when ProxyDaemonConfig.ReadyTimeout is unset.
const DefaultDaemonReadyTimeout = 10 * time.Second

// ProxyDaemonConfig carries the daemon-launch parameters the caller decides, so
// daemonization stays free of config and path-policy concerns.
type ProxyDaemonConfig struct {
	// LogPath is the file the detached daemon's stdout/stderr is redirected to.
	// The caller owns this path (its parent directory must exist).
	LogPath string
	// ReadyTimeout bounds how long to wait for the daemon to write its state
	// file and become live.
	ReadyTimeout time.Duration
}

// Run starts the persistent proxy server in the foreground and blocks until it
// receives SIGINT/SIGTERM. It writes the state file on startup, auto-blocks
// suspicious packages, and records the final blocked count on shutdown.
func Run(ctx context.Context, cfg *config.RuntimeConfig, statePath, host string, port int) error {
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

	localDB := localstore.NewManager(cfg)
	defer func() {
		if cerr := localDB.Close(); cerr != nil {
			log.Warnf("failed to close localdb: %v", cerr)
		}
	}()

	malysisAnalyzer, err := flows.BuildMalysisAnalyzer(ctx, cfg, localDB)
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
	proxyConfig.ListenAddr = listenAddr(host, port)
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

	// Periodically flush events to the cloud while serving so the shutdown flush
	// stays small. See startCloudSyncLoop for the stop-function contract.
	stopSyncLoop := startCloudSyncLoop(cfg)

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

	// Halt the periodic sync (waits for any in-flight drain) before the final
	// flush, so the two never hold the sync lock at once.
	periodicSynced := stopSyncLoop()

	if cs := cloudFlush(cfg, periodicSynced); cs != nil {
		state.CloudSync = cs
		if werr := writeState(statePath, state); werr != nil {
			log.Warnf("failed to write final proxy state: %v", werr)
		}
	}

	return stopErr
}

// cloudFlush drains whatever the periodic sync left and returns the outcome
// (total delivered, including periodicSynced). Returns nil when automatic cloud
// delivery is off (cloud or auto-sync disabled) — same gate as the periodic
// ticker, so auto_sync consistently controls all daemon-driven cloud delivery.
// The daemon does this itself rather than `pmg proxy stop` because, unlike stop,
// it has no proxy env vars and so dials SafeDep directly instead of routing
// through the proxy that is now shutting down. Uses a fresh context since the
// caller's may already be cancelled at shutdown.
func cloudFlush(cfg *config.RuntimeConfig, periodicSynced int) *CloudSyncResult {
	if !cfg.Config.Cloud.Enabled || !cfg.Config.Cloud.AutoSync.Enabled {
		return nil
	}

	synced, err := audit.DrainToCloud(context.Background(), cfg, cloudFlushLockWait, cloudFlushTimeout)
	res := &CloudSyncResult{Synced: periodicSynced + synced}
	if err != nil {
		res.Error = err.Error()
		log.Warnf("cloud event flush failed: %v", err)
	} else {
		log.Infof("Flushed %d events to SafeDep Cloud (%d during the run)", res.Synced, periodicSynced)
	}
	return res
}

// startCloudSyncLoop periodically drains pending audit events to SafeDep Cloud
// while the daemon runs. It returns a stop function that halts the ticker, waits
// for any in-flight drain to finish, and returns the running total of events
// delivered. The stop function must be called before the daemon's final flush so
// the two never hold the sync lock at once. A no-op when cloud sync or auto-sync
// is disabled; the daemon's automatic cloud delivery (periodic ticker and
// shutdown flush alike) honors the auto_sync flag.
func startCloudSyncLoop(cfg *config.RuntimeConfig) func() int {
	if !cfg.Config.Cloud.Enabled || !cfg.Config.Cloud.AutoSync.Enabled {
		return func() int { return 0 }
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	var total int // written only by the goroutine; read after <-done (happens-before)

	go func() {
		defer close(done)
		ticker := time.NewTicker(cloudSyncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				synced, err := audit.DrainToCloud(context.Background(), cfg, cloudSyncTickLockWait, cloudSyncTickTimeout)
				if err != nil {
					if errors.Is(err, audit.ErrSyncInProgress) {
						log.Debugf("periodic cloud sync skipped: another sync in progress")
					} else {
						log.Warnf("periodic cloud sync failed: %v", err)
					}
					continue
				}
				total += synced
				if synced > 0 {
					log.Infof("Periodic cloud sync: flushed %d events", synced)
				}
			}
		}
	}()

	return func() int {
		close(stop)
		<-done
		return total
	}
}

// listenAddr resolves the proxy's bind address from config (host) and the
// --port flag. Host defaults to loopback.
func listenAddr(host string, port int) string {
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
