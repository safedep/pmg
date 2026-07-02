package interceptors

import (
	"fmt"
	"strings"

	"golang.org/x/mod/module"
)

const (
	goRequestLatest = "latest"
	goRequestList   = "list"
	goRequestInfo   = "info"
	goRequestMod    = "mod"
	goRequestZip    = "zip"

	// goRequestSumDB is checksum-database traffic proxied through the module
	// proxy ($GOPROXY/sumdb/...). It is passed through unmodified so go's
	// signature verification stays intact.
	goRequestSumDB = "sumdb"
)

// goModuleInfo is parsed module information from a Go module proxy URL.
type goModuleInfo struct {
	name        string
	version     string
	requestType string
}

var _ packageInfo = (*goModuleInfo)(nil)

func (g *goModuleInfo) GetName() string { return g.name }

func (g *goModuleInfo) GetVersion() string { return g.version }

// IsFileDownload is true only for .zip: the single endpoint that downloads
// module source. .info/.mod are fetched for the entire candidate graph during
// version selection, including modules never selected into the build, so
// analyzing them would block builds over code that never lands in the cache.
func (g *goModuleInfo) IsFileDownload() bool { return g.requestType == goRequestZip }

// goProxyParser parses Go module proxy URLs per the GOPROXY protocol
// (https://go.dev/ref/mod#goproxy-protocol):
//
//	/<module>/@latest            -> latest version metadata
//	/<module>/@v/list            -> version list
//	/<module>/@v/<version>.info  -> version metadata JSON (publish time)
//	/<module>/@v/<version>.mod   -> go.mod file
//	/<module>/@v/<version>.zip   -> module source archive
//	/sumdb/<name>/...            -> proxied checksum-database traffic
//
// Uppercase letters in module path and version arrive escaped as '!'+lowercase
// and are decoded before use as Malysis query keys.
type goProxyParser struct{}

var _ registryURLParser = goProxyParser{}

func (goProxyParser) ParseURL(urlPath string) (packageInfo, error) {
	p := strings.TrimPrefix(urlPath, "/")
	if p == "" {
		return nil, fmt.Errorf("empty go proxy URL path")
	}

	if p == "sumdb" || strings.HasPrefix(p, "sumdb/") {
		return &goModuleInfo{requestType: goRequestSumDB}, nil
	}

	if escaped, ok := strings.CutSuffix(p, "/@latest"); ok {
		name, err := module.UnescapePath(escaped)
		if err != nil {
			return nil, fmt.Errorf("invalid module path in go proxy URL: %w", err)
		}
		return &goModuleInfo{name: name, requestType: goRequestLatest}, nil
	}

	escapedPath, versionPart, ok := strings.Cut(p, "/@v/")
	if !ok {
		return nil, fmt.Errorf("go proxy URL missing /@v/ or /@latest marker")
	}

	name, err := module.UnescapePath(escapedPath)
	if err != nil {
		return nil, fmt.Errorf("invalid module path in go proxy URL: %w", err)
	}

	if versionPart == "list" {
		return &goModuleInfo{name: name, requestType: goRequestList}, nil
	}

	dot := strings.LastIndex(versionPart, ".")
	if dot <= 0 {
		return nil, fmt.Errorf("go proxy URL has no version suffix: %q", versionPart)
	}

	requestType := versionPart[dot+1:]
	switch requestType {
	case goRequestInfo, goRequestMod, goRequestZip:
	default:
		return nil, fmt.Errorf("unrecognized go proxy version suffix: %q", requestType)
	}

	version, err := module.UnescapeVersion(versionPart[:dot])
	if err != nil {
		return nil, fmt.Errorf("invalid version in go proxy URL: %w", err)
	}

	return &goModuleInfo{name: name, version: version, requestType: requestType}, nil
}
