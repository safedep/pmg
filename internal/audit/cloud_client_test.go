package audit

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/cloudauth/cloudauthtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

// encodingRecorder records the compression of each request. gRPC strips the
// grpc-encoding header from the metadata that a handler sees.
type encodingRecorder struct {
	mu        sync.Mutex
	encodings []string
}

func (r *encodingRecorder) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}
func (r *encodingRecorder) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}
func (r *encodingRecorder) HandleConn(context.Context, stats.ConnStats) {}

func (r *encodingRecorder) HandleRPC(_ context.Context, s stats.RPCStats) {
	if header, ok := s.(*stats.InHeader); ok {
		r.mu.Lock()
		r.encodings = append(r.encodings, header.Compression)
		r.mu.Unlock()
	}
}

func unimplemented(any, grpc.ServerStream) error {
	return status.Error(codes.Unimplemented, "the stub records the request encoding only")
}

func TestSyncClientBundleCompressesRequests(t *testing.T) {
	t.Cleanup(config.Reload)
	t.Setenv("PMG_CONFIG_DIR", t.TempDir())
	config.Reload()

	recorder := &encodingRecorder{}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.UnknownServiceHandler(unimplemented), grpc.StatsHandler(recorder))
	served := make(chan error, 1)
	go func() { served <- srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		if err := <-served; !errors.Is(err, grpc.ErrServerStopped) {
			assert.NoError(t, err)
		}
	})
	t.Setenv("SAFEDEP_CLOUD_DATA_ADDR", lis.Addr().String())
	t.Setenv("INSECURE_GRPC_CLIENT_USE_INSECURE_TRANSPORT", "true")

	bundle, err := NewSyncClientBundleWithCredentials(config.Get(), cloudauthtest.KeychainKey(t, time.Time{}))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, bundle.Close()) })

	require.Error(t, bundle.CheckIn(context.Background()))

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	assert.Equal(t, []string{"gzip"}, recorder.encodings)
}
