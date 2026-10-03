package proxyserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/flows"
	"github.com/safedep/pmg/internal/localstore"
	"github.com/safedep/pmg/internal/netenforce"
	"github.com/safedep/pmg/internal/ui"
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

// RunOptions are the parameters of one proxy run that the command line
// decides. The rest comes from the config.
type RunOptions struct {
	StatePath string
	Host      string
	Port      int

	// Enforce turns on kernel enforcement. Linux and root only.
	Enforce bool

	// ExemptExecutables are globs the parent computed before the daemon
	// detached, such as the GitHub runner binaries. They are added to the
	// configured exempt_executables.
	ExemptExecutables []string
}

// Run starts the persistent proxy server in the foreground and blocks until it
// receives SIGINT/SIGTERM. It writes the state file on startup, auto-blocks
// suspicious packages, and records the final blocked count on shutdown.
// With Enforce, it attaches the kernel programs before it reports ready,
// so there is no window in which the proxy runs and a connection is not
// enforced.
func Run(ctx context.Context, cfg *config.RuntimeConfig, opts RunOptions) error {
	// The daemon runs intercepted traffic for every ecosystem, so an
	// unloadable proxy.registries entry must abort here rather than fall
	// back to defaults. Non-install commands (pmg config, proxy stop, ...)
	// are deliberately not gated, so the file stays fixable with pmg.
	if err := config.LoadError(); err != nil {
		return err
	}

	statePath := opts.StatePath
	if existing, err := readState(statePath); err == nil && existing.IsRunning() {
		return fmt.Errorf("proxy already running (pid %d, addr %s) — run 'pmg proxy stop' first", existing.PID, existing.Addr)
	}

	startTime := time.Now()

	var (
		caCert     *certmanager.Certificate
		caCertPath string
		enforcer   netenforce.Enforcer
		policy     netenforce.Policy
		warnings   []string
		err        error
	)
	if opts.Enforce {
		policy, err = enforcePolicy(cfg, opts.ExemptExecutables)
		if err != nil {
			return err
		}
		policy.TraceDecisions = strings.EqualFold(os.Getenv("APP_LOG_LEVEL"), "debug")
		enforcer, caCert, warnings, err = enforcePreflight(cfg, policy)
		if err != nil {
			return err
		}
		caCertPath = certmanager.CACertPath(config.SystemConfigDir())
	} else {
		caCertPath = certmanager.ProxyCABundlePath(cfg.ConfigDir())
		caCert, _, err = flows.SetupCACertificate(cfg.ConfigDir(), caCertPath)
		if err != nil {
			return fmt.Errorf("setup CA certificate: %w", err)
		}
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
	statsCollector := interceptors.NewAnalysisStatsCollector()
	confirmationChan := make(chan *interceptors.ConfirmationRequest, 100)
	go autoBlockConfirmations(confirmationChan)

	interceptorList, err := buildInterceptors(
		malysisAnalyzer, cache, statsCollector, confirmationChan, cfg.Config.Proxy.Registries,
	)
	if err != nil {
		return err
	}

	proxyConfig := pmgproxy.DefaultProxyConfig()
	proxyConfig.ListenAddr = listenAddr(opts.Host, opts.Port)
	proxyConfig.CertManager = certMgr
	proxyConfig.Interceptors = interceptorList
	presenter := ui.ProxyPresenter{Advisory: config.AdvisoryMessage}
	proxyConfig.BlockMessageRenderer = presenter.BlockMessage

	resolver := &destinationResolver{}
	if opts.Enforce {
		proxyConfig.Transparent = true
		proxyConfig.OriginalDestination = resolver
		if addr6 := ipv6LoopbackAddr(); addr6 != "" {
			proxyConfig.AdditionalListenAddrs = []string{addr6}
		}
	}

	server, err := pmgproxy.NewProxyServer(proxyConfig)
	if err != nil {
		return fmt.Errorf("create proxy server: %w", err)
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("start proxy server: %w", err)
	}
	stopServer := func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), serverStopTimeout)
		defer cancel()
		if serr := server.Stop(stopCtx); serr != nil {
			log.Warnf("failed to stop proxy: %v", serr)
		}
	}

	state := State{
		PID:        os.Getpid(),
		Addr:       server.Address(),
		CACertPath: caCertPath,
	}

	var enforceHandle netenforce.Handle
	if opts.Enforce {
		enforceHandle, state.Enforce, err = attachEnforcement(ctx, enforcer, policy, server, warnings)
		if err != nil {
			stopServer()
			return err
		}
		resolver.set(enforceHandle)
	}

	if err := writeState(statePath, state); err != nil {
		if enforceHandle != nil {
			if cerr := enforceHandle.Close(); cerr != nil {
				log.Warnf("failed to detach enforcement after state write failure: %v", cerr)
			}
		}
		stopServer()
		return fmt.Errorf("write proxy state: %w", err)
	}

	log.Infof("PMG persistent proxy running on %s (pid %d)", state.Addr, state.PID)
	if _, err := fmt.Fprint(os.Stderr, startupMessage(state)); err != nil {
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
	// Enforcement stays on while the server drains, so a client that connects
	// now is refused instead of going direct. The kernel detaches at exit in
	// any case.
	stopCtx, cancel := context.WithTimeout(context.Background(), serverStopTimeout)
	defer cancel()
	stopErr := server.Stop(stopCtx)

	if enforceHandle != nil {
		if cerr := enforceHandle.Close(); cerr != nil {
			log.Warnf("failed to detach enforcement: %v", cerr)
		}
	}

	close(confirmationChan)

	// Stats are read after drain so a package analyzed at shutdown is not missed.
	// Persist the blocked count BEFORE the (possibly slow) cloud flush so it
	// survives even if the flush hangs or the daemon is killed mid-flush, which
	// keeps `stop --fail-on-violation` correct in those cases.
	stats := statsCollector.GetStats()
	state.BlockedCount = stats.BlockedCount
	if werr := writeState(statePath, state); werr != nil {
		log.Warnf("failed to write final proxy state: %v", werr)
	}

	// Emit the daemon-lifetime session summary before the final flush so it is
	// delivered alongside the run's other events. Unlike the per-invocation flow,
	// the daemon serves every package manager, so the summary carries no single
	// package manager.
	logSessionSummary(cfg, stats, time.Since(startTime))

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

// attachEnforcement routes eligible connections to the running listeners.
// It returns the handle and the state block, with the policy as the kernel
// resolved it.
func attachEnforcement(ctx context.Context, enforcer netenforce.Enforcer, policy netenforce.Policy, server pmgproxy.ProxyServer, warnings []string) (netenforce.Handle, *EnforceState, error) {
	target := netenforce.Target{}
	addr, err := netip.ParseAddrPort(server.Address())
	if err != nil {
		return nil, nil, fmt.Errorf("parse proxy address %q: %w", server.Address(), err)
	}
	target.Addr = addr

	for _, extra := range server.AdditionalAddresses() {
		if addr6, err := netip.ParseAddrPort(extra); err == nil && addr6.Addr().Is6() {
			target.Addr6 = addr6
		}
	}

	handle, err := enforcer.Attach(ctx, target, policy)
	if err != nil {
		return nil, nil, fmt.Errorf("attach enforcement: %w", err)
	}

	es := &EnforceState{Status: handle.Status(), Warnings: warnings}
	if target.Addr6.IsValid() {
		es.Addr6 = target.Addr6.String()
	}
	return handle, es, nil
}

func startupMessage(state State) string {
	if state.Enforce == nil {
		return fmt.Sprintf("PMG proxy running on %s\nRun: export $(pmg proxy env | xargs)  # or: pmg proxy env >> \"$GITHUB_ENV\"\n", state.Addr)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("PMG proxy running on %s with kernel enforcement (cgroup %s, ports %s)\n",
		state.Addr, state.Enforce.CgroupPath, formatPorts(state.Enforce.Ports)))
	b.WriteString("Every eligible process is routed through the proxy. Run: pmg proxy env >> \"$GITHUB_ENV\"  # trust variables only\n")
	for _, w := range state.Enforce.Warnings {
		b.WriteString(fmt.Sprintf("%s %s\n", ui.Colors.Yellow("⚠"), w))
	}
	return b.String()
}

func formatPorts(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

func buildInterceptors(
	malysisAnalyzer analyzer.PackageVersionAnalyzer,
	cache interceptors.AnalysisCache,
	statsCollector *interceptors.AnalysisStatsCollector,
	confirmationChan chan *interceptors.ConfirmationRequest,
	registries []config.ProxyRegistryConfig,
) ([]pmgproxy.Interceptor, error) {
	factory, err := interceptors.NewInterceptorFactory(
		malysisAnalyzer,
		cache,
		statsCollector,
		confirmationChan,
		interceptors.InterceptorContext{},
		registries,
	)
	if err != nil {
		return nil, err
	}
	return factory.CreateInterceptors(interceptors.SupportedEcosystems()...)
}

// logSessionSummary emits an aggregate session-complete audit event for the
// daemon's lifetime, mapping the proxy stats collector onto SessionData. The
// outcome is blocked when anything was blocked, otherwise success.
func logSessionSummary(cfg *config.RuntimeConfig, stats interceptors.AnalysisStats, duration time.Duration) {
	outcome := audit.OutcomeSuccess
	if stats.BlockedCount > 0 {
		outcome = audit.OutcomeBlocked
	}

	audit.LogSessionSummary(audit.SessionData{
		FlowType:             audit.FlowTypeProxy,
		Outcome:              outcome,
		TotalAnalyzed:        uint32(stats.TotalAnalyzed),
		AllowedCount:         uint32(stats.AllowedCount),
		BlockedCount:         uint32(stats.BlockedCount),
		ConfirmedCount:       uint32(stats.ConfirmedCount),
		CooldownBlockedCount: uint32(stats.CooldownBlockedCount),
		Duration:             duration,
		SandboxEnabled:       cfg.Config.Sandbox.Enabled,
		ParanoidMode:         cfg.Config.Paranoid,
	})
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
