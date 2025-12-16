package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewRequestContext(t *testing.T) {
	tests := []struct {
		name         string
		setupRequest func() *http.Request
		wantError    bool
		assert       func(*testing.T, *RequestContext, error)
	}{
		{
			name: "full URL with hostname",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/path", nil)
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "example.com", ctx.Hostname)
				assert.Equal(t, "GET", ctx.Method)
				assert.NotNil(t, ctx.URL)
				assert.Equal(t, "https://example.com/path", ctx.URL.String())
				assert.Equal(t, "application/json", ctx.Headers.Get("Content-Type"))
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name: "full URL with port",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("POST", "https://api.example.com:8080/api/v1", nil)
				return req
			},
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "api.example.com", ctx.Hostname)
				assert.Equal(t, "POST", ctx.Method)
				assert.NotNil(t, ctx.URL)
				assert.Equal(t, "https://api.example.com:8080/api/v1", ctx.URL.String())
				assert.Empty(t, ctx.Headers)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name: "relative URL with Host header",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/path/to/resource", nil)
				req.Host = "proxy.example.com"
				req.Header.Set("Authorization", "Bearer token123")
				return req
			},
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "proxy.example.com", ctx.Hostname)
				assert.Equal(t, "GET", ctx.Method)
				assert.NotNil(t, ctx.URL)
				assert.Equal(t, "/path/to/resource", ctx.URL.String())
				assert.Equal(t, "Bearer token123", ctx.Headers.Get("Authorization"))
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name: "relative URL with Host header containing port",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("PUT", "/update", nil)
				req.Host = "localhost:3000"
				return req
			},
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "localhost", ctx.Hostname)
				assert.Equal(t, "PUT", ctx.Method)
				assert.NotNil(t, ctx.URL)
				assert.Equal(t, "/update", ctx.URL.String())
				assert.Empty(t, ctx.Headers)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name: "CONNECT method with Host header",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("CONNECT", "", nil)
				req.Host = "secure.example.com:443"
				return req
			},
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "secure.example.com", ctx.Hostname)
				assert.Equal(t, "CONNECT", ctx.Method)
				assert.NotNil(t, ctx.URL)
				assert.Equal(t, "", ctx.URL.String())
				assert.Empty(t, ctx.Headers)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name: "empty hostname fallback",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("DELETE", "/delete", nil)
				// No Host header and no URL hostname
				return req
			},
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Empty(t, ctx.Hostname)
				assert.Equal(t, "DELETE", ctx.Method)
				assert.NotNil(t, ctx.URL)
				assert.Equal(t, "/delete", ctx.URL.String())
				assert.Empty(t, ctx.Headers)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name: "IPv6 address in Host header",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Host = "[::1]:8080"
				return req
			},
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "::1", ctx.Hostname)
				assert.Equal(t, "GET", ctx.Method)
				assert.NotNil(t, ctx.URL)
				assert.Equal(t, "/", ctx.URL.String())
				assert.Empty(t, ctx.Headers)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Data)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			ctx, err := newRequestContext(req)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			tt.assert(t, ctx, err)
		})
	}
}

func TestNewRequestContextFromURL(t *testing.T) {
	tests := []struct {
		name      string
		urlStr    string
		method    string
		wantError bool
		assert    func(*testing.T, *RequestContext, error)
	}{
		{
			name:      "full HTTPS URL",
			urlStr:    "https://api.example.com/v1/users",
			method:    "GET",
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "api.example.com", ctx.Hostname)
				assert.Equal(t, "https", ctx.URL.Scheme)
				assert.Equal(t, "GET", ctx.Method)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Headers)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name:      "full HTTP URL with port",
			urlStr:    "http://localhost:8080/health",
			method:    "POST",
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "localhost", ctx.Hostname)
				assert.Equal(t, "http", ctx.URL.Scheme)
				assert.Equal(t, "POST", ctx.Method)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Headers)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name:      "CONNECT style hostname:port",
			urlStr:    "registry.npmjs.org:443",
			method:    "CONNECT",
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "registry.npmjs.org", ctx.Hostname)
				assert.Equal(t, "https", ctx.URL.Scheme)
				assert.Equal(t, "CONNECT", ctx.Method)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Headers)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name:      "hostname without port",
			urlStr:    "example.com",
			method:    "GET",
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "example.com", ctx.Hostname)
				assert.Equal(t, "https", ctx.URL.Scheme)
				assert.Equal(t, "GET", ctx.Method)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Headers)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name:      "IPv4 address with port",
			urlStr:    "192.168.1.1:8443",
			method:    "PUT",
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "192.168.1.1", ctx.Hostname)
				assert.Equal(t, "https", ctx.URL.Scheme)
				assert.Equal(t, "PUT", ctx.Method)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Headers)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name:      "IPv6 address with port",
			urlStr:    "[2001:db8::1]:443",
			method:    "DELETE",
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "2001:db8::1", ctx.Hostname)
				assert.Equal(t, "https", ctx.URL.Scheme)
				assert.Equal(t, "DELETE", ctx.Method)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Headers)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name:      "URL with path and query",
			urlStr:    "api.service.com:443/v2/data?filter=active",
			method:    "GET",
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "api.service.com", ctx.Hostname)
				assert.Equal(t, "https", ctx.URL.Scheme)
				assert.Equal(t, "GET", ctx.Method)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Headers)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name:      "FTP URL (keeps original scheme)",
			urlStr:    "ftp://files.example.com/upload",
			method:    "PUT",
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Equal(t, "files.example.com", ctx.Hostname)
				assert.Equal(t, "ftp", ctx.URL.Scheme)
				assert.Equal(t, "PUT", ctx.Method)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Headers)
				assert.NotNil(t, ctx.Data)
			},
		},
		{
			name:      "invalid URL with malformed characters",
			urlStr:    "http://[invalid-ipv6",
			method:    "GET",
			wantError: true,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.Error(t, err)
				assert.Nil(t, ctx)
			},
		},
		{
			name:      "empty URL becomes root path",
			urlStr:    "",
			method:    "GET",
			wantError: false,
			assert: func(t *testing.T, ctx *RequestContext, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, ctx)
				assert.Empty(t, ctx.Hostname)
				assert.Equal(t, "https", ctx.URL.Scheme)
				assert.Equal(t, "GET", ctx.Method)
				assert.NotEmpty(t, ctx.RequestID)
				assert.Len(t, ctx.RequestID, 16)
				assert.False(t, ctx.StartTime.IsZero())
				assert.WithinDuration(t, time.Now(), ctx.StartTime, time.Second)
				assert.NotNil(t, ctx.Headers)
				assert.NotNil(t, ctx.Data)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, err := newRequestContextFromURL(tt.urlStr, tt.method)
			tt.assert(t, ctx, err)
		})
	}
}

func TestGenerateRequestIDUniqueness(t *testing.T) {
	ids := make(map[string]bool)

	for i := 0; i < 1000; i++ {
		id, err := generateRequestID()
		assert.NoError(t, err)
		assert.Len(t, id, 16)

		assert.False(t, ids[id], "generateRequestID() produced duplicate ID: %s", id)
		ids[id] = true
	}
}
