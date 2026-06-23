package proxye2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/internal/models"
	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/proxy/interceptors"
	"github.com/stretchr/testify/require"
)

// Harness wires the real proxy, interceptors and analyzer against an in-process
// mock registry and a stub malysis client. It is the single entry point a test
// case uses to register fixtures, drive traffic and assert outcomes.
type Harness struct {
	t *testing.T

	Registry *Registry
	Analyzer *AnalyzerRecorder
	Confirm  *ConfirmController

	stats    *interceptors.AnalysisStatsCollector
	proxy    proxy.ProxyServer
	client   *http.Client
	confChan chan *interceptors.ConfirmationRequest

	dialMu      sync.Mutex
	dialedAddrs []string
}

type options struct {
	pinnedVersions map[string]string
}

type Option func(*options)

// WithPinnedVersions seeds the interceptor's pinned-version context, which
// cooldown uses to report when an explicitly requested version is blocked.
func WithPinnedVersions(pinned map[string]string) Option {
	return func(o *options) { o.pinnedVersions = pinned }
}

func New(t *testing.T, opts ...Option) *Harness {
	t.Helper()

	var o options
	for _, opt := range opts {
		opt(&o)
	}

	caCert, err := certmanager.GenerateCA(certmanager.DefaultCertManagerConfig())
	require.NoError(t, err)

	certMgr, err := certmanager.NewCertificateManagerWithCA(caCert, certmanager.DefaultCertManagerConfig())
	require.NoError(t, err)

	registry := newRegistry()
	rec := newAnalyzerRecorder()
	confirm := newConfirmController()
	stats := interceptors.NewAnalysisStatsCollector()

	malysisAnalyzer, err := analyzer.NewMalysisQueryAnalyzerWithClient(
		&stubAnalyzerClient{rec: rec}, analyzer.MalysisQueryAnalyzerConfig{}, true)
	require.NoError(t, err)

	confChan := make(chan *interceptors.ConfirmationRequest, 10)
	go interceptors.HandleConfirmationRequests(confChan, confirm.interaction(), nil)

	factory := interceptors.NewInterceptorFactory(
		malysisAnalyzer,
		interceptors.NewInMemoryAnalysisCache(),
		stats,
		confChan,
		interceptors.InterceptorContext{PinnedVersions: o.pinnedVersions},
	)

	interceptorList := []proxy.Interceptor{interceptors.NewAuditLoggerInterceptor()}
	for _, eco := range []packagev1.Ecosystem{packagev1.Ecosystem_ECOSYSTEM_NPM, packagev1.Ecosystem_ECOSYSTEM_PYPI} {
		ic, ierr := factory.CreateInterceptor(eco)
		require.NoError(t, ierr)
		interceptorList = append(interceptorList, ic)
	}

	h := &Harness{
		t:        t,
		Registry: registry,
		Analyzer: rec,
		Confirm:  confirm,
		stats:    stats,
		confChan: confChan,
	}

	h.proxy = buildProxy(t, certMgr, registry.addr(), interceptorList, h.recordDial)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert.X509Cert)

	proxyURL, err := url.Parse("http://" + h.proxy.Address())
	require.NoError(t, err)

	h.client = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}

	return h
}

func buildProxy(t *testing.T, certMgr certmanager.CertificateManager, upstreamAddr string, interceptorList []proxy.Interceptor, recordDial func(string)) proxy.ProxyServer {
	t.Helper()

	cfg := proxy.DefaultProxyConfig()
	cfg.CertManager = certMgr
	cfg.Interceptors = interceptorList

	// All upstream connections — MITM'd round-trips and CONNECT tunnels for
	// non-MITM hosts alike — terminate at the mock registry, so no test reaches
	// the network regardless of the hostname being proxied.
	cfg.UpstreamDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		recordDial(addr)
		return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
	}
	// Test-only: the mock's self-signed cert cannot match the real registry SNIs
	// the proxy presents upstream, so verification is skipped for this in-process
	// hop (the same approach proxy/scale_test.go uses).
	cfg.UpstreamTLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402

	server, err := proxy.NewProxyServer(cfg)
	require.NoError(t, err)
	require.NoError(t, server.Start())
	return server
}

// Close stops the proxy first so no interceptor can send on the confirmation
// channel after it is closed.
func (h *Harness) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = h.proxy.Stop(ctx)
	close(h.confChan)
	h.Registry.close()
}

func (h *Harness) Npm() NpmDriver   { return NpmDriver{h: h} }
func (h *Harness) Pypi() PypiDriver { return PypiDriver{h: h} }

func (h *Harness) Stats() interceptors.AnalysisStats { return h.stats.GetStats() }

func (h *Harness) BlockedPackages() []*analyzer.PackageVersionAnalysisResult {
	return h.stats.GetBlockedPackages()
}

func (h *Harness) CooldownBlocks() []models.CooldownBlock { return h.stats.GetCooldownBlocks() }

func (h *Harness) recordDial(addr string) {
	h.dialMu.Lock()
	defer h.dialMu.Unlock()
	h.dialedAddrs = append(h.dialedAddrs, addr)
}

// DialedAddrs returns the upstream addresses the proxy was asked to connect to,
// before redirection to the mock. A non-MITM host appearing here proves its
// CONNECT tunnel went through the override rather than the real network.
func (h *Harness) DialedAddrs() []string {
	h.dialMu.Lock()
	defer h.dialMu.Unlock()
	out := make([]string, len(h.dialedAddrs))
	copy(out, h.dialedAddrs)
	return out
}

// RawClient returns an HTTP client wired through the proxy and trusting the MITM
// CA, for edge cases the install drivers do not model.
func (h *Harness) RawClient() *http.Client { return h.client }

func (h *Harness) get(rawURL string, headers map[string]string) RequestOutcome {
	h.t.Helper()

	out := RequestOutcome{URL: rawURL}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		out.Err = err
		return out
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		out.Err = err
		return out
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		out.Err = err
		return out
	}

	out.StatusCode = resp.StatusCode
	out.Blocked = resp.StatusCode == http.StatusForbidden
	out.Body = string(body)
	return out
}
