package interceptors

import (
	"fmt"
	"strings"

	"github.com/safedep/pmg/internal/cargo"
)

const (
	cargoRequestConfig   = "config"
	cargoRequestIndex    = "index"
	cargoRequestDownload = "download"
)

// cargoCrateInfo is parsed crate information from a Cargo registry URL.
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
	if info, ok := parseCargoIndexPath(urlPath); ok {
		return info, nil
	}
	return nil, fmt.Errorf("unrecognized cargo index URL path: %q", urlPath)
}

// cargoDownloadParser parses .crate download URLs on static.crates.io, which
// serves them under /crates:
//
//	/crates/<name>/<version>/download        (cargo's default dl template)
//	/crates/<name>/<name>-<version>.crate    (direct CDN path)
type cargoDownloadParser struct{}

var _ registryURLParser = cargoDownloadParser{}

func (cargoDownloadParser) ParseURL(urlPath string) (packageInfo, error) {
	segments := strings.Split(strings.Trim(urlPath, "/"), "/")
	if (len(segments) == 3 || len(segments) == 4) && segments[0] == "crates" {
		info, ok := parseCargoDownloadPath(segments)
		if ok && info.name == strings.ToLower(segments[1]) {
			return info, nil
		}
	}
	return nil, fmt.Errorf("unrecognized cargo download URL path: %q", urlPath)
}

// cargoCustomParser parses the URLs of a sparse registry from
// proxy.registries. One endpoint can serve the index and the downloads, as
// Gitea and Kellnr do, so the parser reads both: the config.json and index
// files at the base path, and a download at any depth under it. A dl URL with
// no {crate} and {version} in the path, such as one that names only
// {sha256-checksum}, stays unparsed. PMG never guesses at a path shape.
type cargoCustomParser struct{}

var _ registryURLParser = cargoCustomParser{}

func (cargoCustomParser) ParseURL(urlPath string) (packageInfo, error) {
	if info, ok := parseCargoIndexPath(urlPath); ok {
		return info, nil
	}
	if info, ok := parseCargoDownloadPath(strings.Split(strings.Trim(urlPath, "/"), "/")); ok {
		return info, nil
	}
	return nil, fmt.Errorf("unrecognized cargo registry URL path: %q", urlPath)
}

func parseCargoIndexPath(urlPath string) (*cargoCrateInfo, bool) {
	p := strings.Trim(urlPath, "/")
	if p == "config.json" {
		return &cargoCrateInfo{requestType: cargoRequestConfig}, true
	}

	// The name check keeps a download such as /se/rd/serde-1.0.0.crate, from
	// a {lowerprefix} dl template, from passing as an index file and skipping
	// analysis.
	name := p[strings.LastIndex(p, "/")+1:]
	if !cargo.IsCrateName(name) || cargoSparseIndexPath(name) != p {
		return nil, false
	}
	return &cargoCrateInfo{name: name, requestType: cargoRequestIndex}, true
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

// parseCargoDownloadPath reads a .crate download from the last path segments:
//
//	.../<name>/<version>/download   (the path cargo appends to a dl URL with no markers)
//	.../<name>-<version>.crate      (a dl template such as {prefix}/{crate}-{version}.crate)
//
// The version must be a full semver version, so an index file such as
// /do/wn/download never matches.
func parseCargoDownloadPath(segments []string) (*cargoCrateInfo, bool) {
	last := segments[len(segments)-1]
	if last == "download" && len(segments) >= 3 {
		name, version := segments[len(segments)-3], segments[len(segments)-2]
		if cargo.IsCrateName(name) && cargo.IsExactVersion(version) {
			return newCargoDownload(name, version), true
		}
		return nil, false
	}

	stem, ok := strings.CutSuffix(last, ".crate")
	if !ok {
		return nil, false
	}
	// A crate name has no dot and a version starts with "<n>.<n>.", so at
	// most one hyphen splits the stem into a valid name and a valid version.
	for index, char := range stem {
		if char != '-' {
			continue
		}
		name, version := stem[:index], stem[index+1:]
		if cargo.IsCrateName(name) && cargo.IsExactVersion(version) {
			return newCargoDownload(name, version), true
		}
	}
	return nil, false
}

// newCargoDownload lowercases the name. Crate names are case-insensitive:
// download URLs carry the canonical case while index paths are lowercase, so
// analysis caching and PURL policy matching (trusted_packages,
// dependency_cooldown.skip) see one identity across both paths.
func newCargoDownload(name, version string) *cargoCrateInfo {
	return &cargoCrateInfo{name: strings.ToLower(name), version: version, requestType: cargoRequestDownload}
}
