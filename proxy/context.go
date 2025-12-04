package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func newRequestContext(req *http.Request) *RequestContext {
	var hostname string
	// Extract hostname - for MITM'd requests, URL might be relative
	// so we need to check the Host header
	if req.URL != nil {
		hostname = req.URL.Hostname()
	}

	if hostname == "" && req.Host != "" {
		// For MITM requests, the URL is relative but Host header contains the hostname
		hostname = req.Host
		if host, _, err := net.SplitHostPort(req.Host); err == nil {
			hostname = host
		}
	}

	return &RequestContext{
		URL:       req.URL,
		Method:    req.Method,
		Headers:   req.Header,
		Hostname:  hostname,
		RequestID: generateRequestID(),
		StartTime: time.Now(),
		Data:      make(map[string]interface{}),
	}
}

func newRequestContextFromURL(urlStr string, method string) (*RequestContext, error) {
	// For CONNECT requests, we receive "hostname:port" (e.g., "registry.npmjs.org:443")
	// url.Parse treats this as "scheme:path", so we need to add "//" to parse correctly
	if !strings.Contains(urlStr, "://") {
		urlStr = "//" + urlStr
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	// If URL doesn't have a scheme, add https (typical for CONNECT)
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}

	return &RequestContext{
		URL:       parsedURL,
		Method:    method,
		Headers:   make(http.Header),
		Hostname:  parsedURL.Hostname(),
		RequestID: generateRequestID(),
		StartTime: time.Now(),
		Data:      make(map[string]interface{}),
	}, nil
}

func generateRequestID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
