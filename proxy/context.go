package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func newRequestContext(req *http.Request) (*RequestContext, error) {
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

	requestID, err := generateRequestID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	return &RequestContext{
		URL:       req.URL,
		Method:    req.Method,
		Headers:   req.Header,
		Hostname:  hostname,
		RequestID: requestID,
		StartTime: time.Now(),
		Data:      make(map[string]interface{}),
	}, nil
}

func newRequestContextFromURL(urlStr string, method string) (*RequestContext, error) {
	// For CONNECT requests, we receive "hostname:port" (e.g., "registry.npmjs.org:443")
	// url.Parse treats this as "scheme:path", so we need to add "//" to parse correctly
	if !strings.Contains(urlStr, "://") {
		urlStr = "//" + urlStr
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	// If URL doesn't have a scheme, add https (typical for CONNECT)
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	}

	requestID, err := generateRequestID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	return &RequestContext{
		URL:       parsedURL,
		Method:    method,
		Headers:   make(http.Header),
		Hostname:  parsedURL.Hostname(),
		RequestID: requestID,
		StartTime: time.Now(),
		Data:      make(map[string]interface{}),
	}, nil
}

func generateRequestID() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
