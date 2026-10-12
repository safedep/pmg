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
		wantURLs  []string
	}{
		{
			name:      "empty defaults to public proxy without direct",
			goproxy:   "",
			wantChild: "https://proxy.golang.org",
			wantURLs:  []string{"https://proxy.golang.org"},
		},
		{
			name:      "default value drops direct",
			goproxy:   "https://proxy.golang.org,direct",
			wantChild: "https://proxy.golang.org",
			wantURLs:  []string{"https://proxy.golang.org"},
		},
		{
			name:      "pipe separator collapses to comma",
			goproxy:   "https://corp.example.com|https://proxy.golang.org|direct",
			wantChild: "https://corp.example.com,https://proxy.golang.org",
			wantURLs:  []string{"https://corp.example.com", "https://proxy.golang.org"},
		},
		{
			name:      "direct only injects public proxy",
			goproxy:   "direct",
			wantChild: "https://proxy.golang.org",
			wantURLs:  []string{"https://proxy.golang.org"},
		},
		{
			name:      "off is kept and nothing is intercepted",
			goproxy:   "off",
			wantChild: "off",
			wantURLs:  nil,
		},
		{
			name:      "proxy with base path keeps full base URL",
			goproxy:   "https://corp.example.com:8443/goproxy,direct",
			wantChild: "https://corp.example.com:8443/goproxy",
			wantURLs:  []string{"https://corp.example.com:8443/goproxy"},
		},
		{
			name:      "unschemed entry defaults to https (go behavior)",
			goproxy:   "proxy.corp.internal,direct",
			wantChild: "https://proxy.corp.internal",
			wantURLs:  []string{"https://proxy.corp.internal"},
		},
		{
			name:      "unschemed entry with port",
			goproxy:   "proxy.corp.internal:8443",
			wantChild: "https://proxy.corp.internal:8443",
			wantURLs:  []string{"https://proxy.corp.internal:8443"},
		},
		{
			name:      "http proxy is kept and intercepted",
			goproxy:   "http://insecure.example.com",
			wantChild: "http://insecure.example.com",
			wantURLs:  []string{"http://insecure.example.com"},
		},
		{
			name:      "file proxy kept verbatim with no host",
			goproxy:   "file:///var/goproxy,direct",
			wantChild: "file:///var/goproxy",
			wantURLs:  nil,
		},
		{
			name:      "credentials stay in the child and leave the analyzed URL",
			goproxy:   "https://user:token@corp.example.com/goproxy,direct",
			wantChild: "https://user:token@corp.example.com/goproxy",
			wantURLs:  []string{"https://corp.example.com/goproxy"},
		},
		{
			name:      "whitespace and empty entries are ignored",
			goproxy:   " https://proxy.golang.org , ,direct ",
			wantChild: "https://proxy.golang.org",
			wantURLs:  []string{"https://proxy.golang.org"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			child, urls := normalizeGoProxy(tc.goproxy)
			assert.Equal(t, tc.wantChild, child)
			assert.Equal(t, tc.wantURLs, urls)
		})
	}
}
