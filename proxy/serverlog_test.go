package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rejectedLines struct {
	mu    sync.Mutex
	lines []string
}

func (r *rejectedLines) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, line)
}

func (r *rejectedLines) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.lines)
}

func TestServerLogReportsRejectedCertificatesOncePerInterval(t *testing.T) {
	var got rejectedLines
	l := &serverLog{onRejected: got.add}

	for _, line := range []string{
		"http: TLS handshake error from 172.17.0.4:40140: remote error: tls: unknown certificate authority\n",
		"http: TLS handshake error from 172.17.0.4:40142: local error: tls: bad record MAC\n",
		"http: TLS handshake error from 10.0.0.1:1: EOF\n",
	} {
		n, err := l.Write([]byte(line))
		require.NoError(t, err)
		assert.Equal(t, len(line), n)
	}
	require.Equal(t, 1, got.count(), "one report per interval")
	assert.Contains(t, got.lines[0], "172.17.0.4:40140")

	l.lastHint = time.Now().Add(-2 * hintInterval)
	_, err := l.Write([]byte("http: TLS handshake error from 172.17.0.5:1: remote error: tls: certificate unknown\n"))
	require.NoError(t, err)
	assert.Equal(t, 2, got.count(), "a new interval allows a new report")
}

// A client that does not trust the server certificate aborts the handshake
// with an alert, and http.Server reports it through ErrorLog. This pins the
// path the trust hint depends on.
func TestServerLogSeesARejectedCertificate(t *testing.T) {
	var got rejectedLines
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ErrorLog = newServerLog(got.add)
	srv.StartTLS()
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}}
	_, err := client.Get(srv.URL)
	require.Error(t, err)

	assert.Eventually(t, func() bool { return got.count() == 1 }, 2*time.Second, 10*time.Millisecond)
}
