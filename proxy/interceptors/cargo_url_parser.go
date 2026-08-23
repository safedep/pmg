package interceptors

import (
	"fmt"
	"strings"
)

const (
	cargoRequestConfig   = "config"
	cargoRequestIndex    = "index"
	cargoRequestDownload = "download"
)

// cargoCrateInfo is parsed crate information from a crates.io registry URL.
type cargoCrateInfo struct {
	name        string
	version     string
	requestType string
}

var _ packageInfo = (*cargoCrateInfo)(nil)

func (c *cargoCrateInfo) GetName() string { return c.name }

func (c *cargoCrateInfo) GetVersion() string { return c.version }

// IsFileDownload is true only for .crate downloads: the single endpoint that
// fetches crate source. Index files are metadata fetched for the whole
// candidate graph during resolution, including crates never selected into the
// build.
func (c *cargoCrateInfo) IsFileDownload() bool { return c.requestType == cargoRequestDownload }

// cargoIndexParser parses sparse-index URLs on index.crates.io
// (https://doc.rust-lang.org/cargo/reference/registry-index.html):
//
//	/config.json          -> registry configuration (dl/api base URLs)
//	/1/<name>             -> index file, 1-character crate names
//	/2/<name>             -> index file, 2-character crate names
//	/3/<c>/<name>         -> index file, 3-character crate names (<c> = first char)
//	/<aa>/<bb>/<name>     -> index file, longer names (first two 2-char chunks)
//
// Index paths are always lowercase; the crate's canonical name is inside the
// NDJSON body.
type cargoIndexParser struct{}

var _ registryURLParser = cargoIndexParser{}

func (cargoIndexParser) ParseURL(urlPath string) (packageInfo, error) {
	p := strings.Trim(urlPath, "/")
	if p == "" {
		return nil, fmt.Errorf("empty cargo index URL path")
	}

	if p == "config.json" {
		return &cargoCrateInfo{requestType: cargoRequestConfig}, nil
	}

	segments := strings.Split(p, "/")
	name := segments[len(segments)-1]
	if name == "" || cargoSparseIndexPath(name) != p {
		return nil, fmt.Errorf("unrecognized cargo index URL path: %q", urlPath)
	}

	return &cargoCrateInfo{name: name, requestType: cargoRequestIndex}, nil
}

// cargoSparseIndexPath returns the sparse-index file path (without leading
// slash) for a crate name, per the registry index layout.
func cargoSparseIndexPath(name string) string {
	lower := strings.ToLower(name)
	switch len(lower) {
	case 0:
		return ""
	case 1:
		return "1/" + lower
	case 2:
		return "2/" + lower
	case 3:
		return "3/" + lower[:1] + "/" + lower
	default:
		return lower[:2] + "/" + lower[2:4] + "/" + lower
	}
}

// cargoDownloadParser parses .crate download URLs on static.crates.io. Both
// URL shapes the CDN serves are recognized:
//
//	/crates/<name>/<version>/download        (cargo's default dl template)
//	/crates/<name>/<name>-<version>.crate    (direct CDN path)
type cargoDownloadParser struct{}

var _ registryURLParser = cargoDownloadParser{}

func (cargoDownloadParser) ParseURL(urlPath string) (packageInfo, error) {
	segments := strings.Split(strings.Trim(urlPath, "/"), "/")
	if len(segments) < 3 || segments[0] != "crates" || segments[1] == "" {
		return nil, fmt.Errorf("unrecognized cargo download URL path: %q", urlPath)
	}

	// crates.io names are case-insensitive; download URLs carry the crate's
	// canonical case while index paths are lowercase. Names are normalized to
	// lowercase so analysis caching and PURL policy matching (trusted_packages,
	// dependency_cooldown.skip) see one identity across both paths.
	name := segments[1]

	if len(segments) == 4 && segments[3] == "download" && segments[2] != "" {
		return &cargoCrateInfo{name: strings.ToLower(name), version: segments[2], requestType: cargoRequestDownload}, nil
	}

	if len(segments) == 3 {
		if file, ok := strings.CutSuffix(segments[2], ".crate"); ok {
			version, found := strings.CutPrefix(file, name+"-")
			if found && version != "" {
				return &cargoCrateInfo{name: strings.ToLower(name), version: version, requestType: cargoRequestDownload}, nil
			}
		}
	}

	return nil, fmt.Errorf("unrecognized cargo download URL path: %q", urlPath)
}
