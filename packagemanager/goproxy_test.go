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
		wantHosts []string
	}{
		{
			name:      "empty defaults to public proxy without direct",
			goproxy:   "",
			wantChild: "https://proxy.golang.org",
			wantHosts: []string{"proxy.golang.org"},
		},
		{
			name:      "default value drops direct",
			goproxy:   "https://proxy.golang.org,direct",
			wantChild: "https://proxy.golang.org",
			wantHosts: []string{"proxy.golang.org"},
		},
		{
			name:      "pipe separator collapses to comma",
			goproxy:   "https://corp.example.com|https://proxy.golang.org|direct",
			wantChild: "https://corp.example.com,https://proxy.golang.org",
			wantHosts: []string{"corp.example.com", "proxy.golang.org"},
		},
		{
			name:      "direct only injects public proxy",
			goproxy:   "direct",
			wantChild: "https://proxy.golang.org",
			wantHosts: []string{"proxy.golang.org"},
		},
		{
			name:      "off is kept and nothing is intercepted",
			goproxy:   "off",
			wantChild: "off",
			wantHosts: nil,
		},
		{
			name:      "custom proxy with path keeps hostname only",
			goproxy:   "https://corp.example.com:8443/goproxy,direct",
			wantChild: "https://corp.example.com:8443/goproxy",
			wantHosts: []string{"corp.example.com"},
		},
		{
			name:      "http proxy is kept and intercepted",
			goproxy:   "http://insecure.example.com",
			wantChild: "http://insecure.example.com",
			wantHosts: []string{"insecure.example.com"},
		},
		{
			name:      "file proxy kept verbatim with no host",
			goproxy:   "file:///var/goproxy,direct",
			wantChild: "file:///var/goproxy",
			wantHosts: nil,
		},
		{
			name:      "whitespace and empty entries are ignored",
			goproxy:   " https://proxy.golang.org , ,direct ",
			wantChild: "https://proxy.golang.org",
			wantHosts: []string{"proxy.golang.org"},
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
