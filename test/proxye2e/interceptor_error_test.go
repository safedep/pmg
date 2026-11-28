package proxye2e

import (
	"errors"
	"net/http"
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingInterceptor struct{}

func (failingInterceptor) Name() string                               { return "failing" }
func (failingInterceptor) ShouldIntercept(*proxy.RequestContext) bool { return true }
func (failingInterceptor) HandleRequest(*proxy.RequestContext) (*proxy.InterceptorResponse, error) {
	return nil, errors.New("rule store unavailable")
}

func TestProxyFlow_InterceptorError(t *testing.T) {
	const tarballPath = "/flaky/-/flaky-1.0.0.tgz"

	var cases []TestCase
	for _, mode := range []struct {
		name     string
		paranoid bool
		insecure bool
		blocked  bool
	}{
		{name: "default mode allows"},
		{name: "paranoid mode blocks with 503", paranoid: true, blocked: true},
		{name: "insecure installation wins over paranoid mode", paranoid: true, insecure: true},
	} {
		cases = append(cases, TestCase{
			Name:    mode.name,
			Options: []Option{WithInterceptor(failingInterceptor{})},
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.Paranoid = mode.paranoid
				rc.InsecureInstallation = mode.insecure
			},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "flaky", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("flaky", "1.0.0", Clean())
			},
			Exec: func(h *Harness) ExecResult {
				var res ExecResult
				res.add(h.Npm().Download("flaky", "1.0.0"))
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				r := lastRequest(t, res)
				events := h.Audit.Events(audit.EventTypeNoVerdictBlocked)

				if !mode.blocked {
					assert.Equal(t, http.StatusOK, r.StatusCode)
					assert.True(t, h.Registry.Requested("registry.npmjs.org", tarballPath))
					assert.Empty(t, h.Blocks())
					assert.Empty(t, events)
					return
				}

				assert.Equal(t, http.StatusServiceUnavailable, r.StatusCode)
				assert.True(t, r.Blocked)
				assert.Contains(t, r.Body, "PMG could not check this request")
				assert.False(t, h.Registry.Requested("registry.npmjs.org", tarballPath))
				assert.Equal(t, []Block{{Reason: proxy.BlockReasonNoVerdict}}, h.Blocks())
				require.Len(t, events, 1)
				assert.Nil(t, events[0].PackageVersion)
				assert.ErrorContains(t, events[0].Error, "interceptor failing: rule store unavailable")
			},
		})
	}
	RunCases(t, cases)
}
