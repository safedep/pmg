package flows

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/sandbox/executor"
)

// networkProxyTunnelTimeout is the wall-clock limit of one connection
// through the exec proxy. A coding agent holds a connection to its model
// API for hours. The package manager default of 30 minutes would cut it.
const networkProxyTunnelTimeout = 24 * time.Hour

const networkProxyStopTimeout = 5 * time.Second

// NetworkProxy is the exec proxy. It applies the network block of a
// resolution to a program that is not a package manager. It has no
// interceptors and does not terminate TLS, so it reads no traffic. It
// decides each destination by host and port and records the run as the
// package manager proxy does.
type NetworkProxy struct {
	addr string
	stop func() NetworkOutcome
}

// StartNetworkProxy starts the proxy on a loopback port.
func StartNetworkProxy(res *executor.Resolution) (*NetworkProxy, error) {
	run := newNetworkRun(res)

	cfg := proxy.DefaultProxyConfig()
	cfg.EnableMITM = false
	cfg.ServerReadWriteTimeout = networkProxyTunnelTimeout
	cfg.OnNetworkDecision = run.record
	cfg.BlockMessageRenderer = ui.ProxyPresenter{Advisory: config.AdvisoryMessage}.BlockMessage
	applyNetworkPolicy(cfg, res)

	server, err := proxy.NewProxyServer(cfg)
	if err != nil {
		return nil, fmt.Errorf("create network proxy: %w", err)
	}
	if err := server.Start(); err != nil {
		return nil, fmt.Errorf("start network proxy: %w", err)
	}

	p := &NetworkProxy{addr: server.Address()}
	p.stop = sync.OnceValue(func() NetworkOutcome {
		ctx, cancel := context.WithTimeout(context.Background(), networkProxyStopTimeout)
		defer cancel()
		if err := server.Stop(ctx); err != nil {
			log.Errorf("failed to stop the network proxy: %v", err)
		}
		return run.finish()
	})
	return p, nil
}

// Addr is the listen address, host:port.
func (p *NetworkProxy) Addr() string { return p.addr }

// Env is the environment that routes a program through the proxy.
func (p *NetworkProxy) Env() []string { return packagemanager.ProxyEnv(p.addr) }

// Stop drains the proxy, records the run and returns what the report
// shows. A second call returns the same outcome without a second record.
func (p *NetworkProxy) Stop() NetworkOutcome { return p.stop() }
