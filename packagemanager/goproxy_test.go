package packagemanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeGoProxy(t *testing.T) {
	cases := []struct {
		name      string
		goproxy   string
		wantChild string
		wantHosts map[string]string
	}{
		{
			name:      "empty defaults to public proxy without direct",
			goproxy:   "",
			wantChild: "https://proxy.golang.org",
			wantHosts: map[string]string{"proxy.golang.org": "https://proxy.golang.org"},
		},
		{
			name:      "default value drops direct",
			goproxy:   "https://proxy.golang.org,direct",
			wantChild: "https://proxy.golang.org",
			wantHosts: map[string]string{"proxy.golang.org": "https://proxy.golang.org"},
		},
		{
			name:      "pipe separator collapses to comma",
			goproxy:   "https://corp.example.com|https://proxy.golang.org|direct",
			wantChild: "https://corp.example.com,https://proxy.golang.org",
			wantHosts: map[string]string{
				"corp.example.com": "https://corp.example.com",
				"proxy.golang.org": "https://proxy.golang.org",
			},
		},
		{
			name:      "direct only injects public proxy",
			goproxy:   "direct",
			wantChild: "https://proxy.golang.org",
			wantHosts: map[string]string{"proxy.golang.org": "https://proxy.golang.org"},
		},
		{
			name:      "off is kept and nothing is intercepted",
			goproxy:   "off",
			wantChild: "off",
			wantHosts: map[string]string{},
		},
		{
			name:      "proxy with base path keeps full base URL",
			goproxy:   "https://corp.example.com:8443/goproxy,direct",
			wantChild: "https://corp.example.com:8443/goproxy",
			wantHosts: map[string]string{"corp.example.com": "https://corp.example.com:8443/goproxy"},
		},
		{
			name:      "unschemed entry defaults to https (go behavior)",
			goproxy:   "proxy.corp.internal,direct",
			wantChild: "https://proxy.corp.internal",
			wantHosts: map[string]string{"proxy.corp.internal": "https://proxy.corp.internal"},
		},
		{
			name:      "unschemed entry with port",
			goproxy:   "proxy.corp.internal:8443",
			wantChild: "https://proxy.corp.internal:8443",
			wantHosts: map[string]string{"proxy.corp.internal": "https://proxy.corp.internal:8443"},
		},
		{
			name:      "http proxy is kept and intercepted",
			goproxy:   "http://insecure.example.com",
			wantChild: "http://insecure.example.com",
			wantHosts: map[string]string{"insecure.example.com": "http://insecure.example.com"},
		},
		{
			name:      "file proxy kept verbatim with no host",
			goproxy:   "file:///var/goproxy,direct",
			wantChild: "file:///var/goproxy",
			wantHosts: map[string]string{},
		},
		{
			name:      "whitespace and empty entries are ignored",
			goproxy:   " https://proxy.golang.org , ,direct ",
			wantChild: "https://proxy.golang.org",
			wantHosts: map[string]string{"proxy.golang.org": "https://proxy.golang.org"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			child, hosts := normalizeGoProxy(tc.goproxy)
			assert.Equal(t, tc.wantChild, child)
			assert.Equal(t, tc.wantHosts, hosts)
		})
	}
}
