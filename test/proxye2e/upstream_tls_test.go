package proxye2e

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// largeWriteDropper models a network path that drops a write larger than one
// TCP segment. The connection stays open and nothing comes back.
type largeWriteDropper struct{ net.Conn }

const tcpSegmentPayload = 1400

func (c largeWriteDropper) Write(b []byte) (int, error) {
	if len(b) > tcpSegmentPayload {
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func TestProxyFlow_UpstreamPathDropsLargeClientHello(t *testing.T) {
	RunCases(t, []TestCase{
		{
			Name: "registry answers when the path drops a post-quantum ClientHello",
			Options: []Option{WithUpstreamConn(func(c net.Conn) net.Conn {
				return largeWriteDropper{Conn: c}
			})},
			Setup: func(h *Harness) {
				h.Registry.AddPypi(PypiPackage{Name: "six",
					Versions: []PypiVersion{{Version: "1.16.0", PublishedAt: old()}}})
			},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.Pypi().FetchSimple("six").Outcome)
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				require.Len(t, res.Requests, 1)
				require.NoError(t, res.Requests[0].Err)
				assert.Equal(t, 200, res.Requests[0].StatusCode)
				assert.True(t, h.Registry.Requested("pypi.org", "/simple/six/"))
			},
		},
	})
}
