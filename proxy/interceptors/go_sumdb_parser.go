package interceptors

import (
	"fmt"
	"strings"
)

// sumdbModuleInfo represents parsed checksum-database request metadata.
// See https://go.dev/ref/mod#checksum-database
type sumdbModuleInfo struct {
	name        string
	version     string
	requestType string // supported, lookup, latest, tile
}

var _ packageInfo = (*sumdbModuleInfo)(nil)

func (s *sumdbModuleInfo) GetName() string {
	return s.name
}

func (s *sumdbModuleInfo) GetVersion() string {
	return s.version
}

func (s *sumdbModuleInfo) IsFileDownload() bool {
	return false
}

type sumdbParser struct{}

var _ registryURLParser = sumdbParser{}

func (sumdbParser) ParseURL(urlPath string) (packageInfo, error) {
	urlPath = strings.TrimLeft(urlPath, "/")
	if urlPath == "" {
		return &sumdbModuleInfo{requestType: "root"}, nil
	}

	switch {
	case urlPath == "supported":
		return &sumdbModuleInfo{requestType: "supported"}, nil
	case strings.HasPrefix(urlPath, "lookup/"):
		return parseSumdbModuleSpec(strings.TrimPrefix(urlPath, "lookup/"), "lookup")
	case strings.HasPrefix(urlPath, "latest/"):
		return parseSumdbModuleSpec(strings.TrimPrefix(urlPath, "latest/"), "latest")
	case strings.HasPrefix(urlPath, "tile/"):
		return &sumdbModuleInfo{requestType: "tile"}, nil
	default:
		return nil, fmt.Errorf("unrecognized sumdb URL path: %s", urlPath)
	}
}

func parseSumdbModuleSpec(spec, requestType string) (packageInfo, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty module spec in sumdb %s URL", requestType)
	}

	lastAt := strings.LastIndex(spec, "@")
	if lastAt <= 0 {
		return &sumdbModuleInfo{name: spec, requestType: requestType}, nil
	}

	name := strings.TrimSpace(spec[:lastAt])
	version := strings.TrimSpace(spec[lastAt+1:])
	if name == "" {
		return nil, fmt.Errorf("empty module name in sumdb URL")
	}

	return &sumdbModuleInfo{
		name:        name,
		version:     version,
		requestType: requestType,
	}, nil
}
