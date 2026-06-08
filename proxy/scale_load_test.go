package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestLoadHTTP2UpstreamConcurrent hammers the MITM proxy with many concurrent
// workers that reuse keep-alive connections (mimicking npm/pip socket pools),
// against an HTTP/2 upstream with a bounded MaxConcurrentStreams (mimicking
// registries fronted by Cloudflare). It reports failure counts and types so we
// can observe whether the proxy drops connections under load.
func TestLoadHTTP2UpstreamConcurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}

	const (
		workers          = 80
		reqsPerWorker    = 40
		payload          = 32 * 1024
		upstreamLatency  = 5 * time.Millisecond
		analyzeLatency   = 10 * time.Millisecond
		maxConcurStreams = 50
	)

	var upstreamConns atomic.Int64

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(upstreamLatency)
		_, _ = w.Write(make([]byte, payload))
	})

	upstream := httptest.NewUnstartedServer(handler)
	upstream.EnableHTTP2 = true
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			upstreamConns.Add(1)
		}
	}
	// Bound concurrent streams per h2 connection like a real CDN.
	if err := http2.ConfigureServer(upstream.Config, &http2.Server{MaxConcurrentStreams: maxConcurStreams}); err != nil {
		t.Fatalf("configure h2: %v", err)
	}
	upstream.StartTLS()
	defer upstream.Close()

	host := mustHost(t, upstream.URL)
	_, client := buildReproProxy(t, host, 30*time.Minute, analyzeLatency)
	// Reuse connections aggressively across workers.
	client.Transport.(*http.Transport).MaxIdleConnsPerHost = workers
	client.Transport.(*http.Transport).MaxConnsPerHost = workers

	var (
		wg        sync.WaitGroup
		fail      atomic.Int64
		short     atomic.Int64
		ok        atomic.Int64
		firstErr  atomic.Value
		startTime = time.Now()
	)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < reqsPerWorker; i++ {
				resp, err := client.Get(fmt.Sprintf("%s/pkg-%d-%d.tgz", upstream.URL, id, i))
				if err != nil {
					fail.Add(1)
					firstErr.CompareAndSwap(nil, err.Error())
					continue
				}
				n, err := io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					fail.Add(1)
					firstErr.CompareAndSwap(nil, err.Error())
					continue
				}
				if n != payload {
					short.Add(1)
					continue
				}
				ok.Add(1)
			}
		}(w)
	}
	wg.Wait()

	total := workers * reqsPerWorker
	t.Logf("total=%d ok=%d fail=%d short=%d elapsed=%s upstreamConns=%d",
		total, ok.Load(), fail.Load(), short.Load(), time.Since(startTime), upstreamConns.Load())
	if fe := firstErr.Load(); fe != nil {
		t.Logf("first error: %v", fe)
	}
}
