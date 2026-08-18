package interceptors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/proxy"
)

// advertisedArtifact is a package artifact URL discovered from registry
// metadata, together with the package identity it was advertised for.
type advertisedArtifact struct {
	URL      *url.URL
	Identity artifactIdentity
}

// parseNpmMetadataArtifacts extracts artifact URLs advertised by an npm
// packument. It reads only the standard "name", "versions.*.name",
// "versions.*.version", and "versions.*.dist.tarball" fields, so it works for
// both full and abbreviated (install-v1) packument shapes. Every other field
// is ignored.
//
// A version entry is skipped, not treated as an error, when its shape does
// not decode, when its map key disagrees with its own "version" field, or
// when its resolved name or version is empty, whitespace-only, or contains a
// control character. This keeps one malformed or inconsistent entry from
// discarding the rest of an otherwise usable packument.
func parseNpmMetadataArtifacts(base *url.URL, body []byte) ([]advertisedArtifact, error) {
	if base == nil {
		return nil, fmt.Errorf("metadata base URL is required")
	}

	var packument struct {
		Name     string                     `json:"name"`
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(body, &packument); err != nil {
		return nil, fmt.Errorf("failed to unmarshal npm packument")
	}

	artifacts := make([]advertisedArtifact, 0, len(packument.Versions))
	for key, raw := range packument.Versions {
		var entry struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Dist    struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			log.Debugf("Skipping npm packument version entry with an unparseable shape")
			continue
		}

		// The packument contract keys "versions" by the entry's own version
		// string. A mismatch means the registry response is inconsistent, so
		// the entry's identity cannot be trusted.
		if entry.Version != "" && key != entry.Version {
			continue
		}

		name := entry.Name
		if !identityFieldValid(name) {
			name = packument.Name
		}
		if !identityFieldValid(name) || !identityFieldValid(entry.Version) || entry.Dist.Tarball == "" {
			continue
		}

		ref, err := url.Parse(entry.Dist.Tarball)
		if err != nil {
			log.Debugf("Skipping npm packument version with an unparseable tarball reference")
			continue
		}

		artifacts = append(artifacts, advertisedArtifact{
			URL:      base.ResolveReference(ref),
			Identity: artifactIdentity{Name: name, Version: entry.Version},
		})
	}

	return artifacts, nil
}

// identityFieldValid reports whether s is usable as a package name or
// version: non-empty once trimmed, and free of control characters. Shared by
// every ecosystem's metadata discovery, since the requirement is the same
// regardless of what the field is called upstream (npm tarball name/version,
// pypi filename-derived name/version, and so on).
func identityFieldValid(s string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// npmMetadataDiscoveryModifier returns a response modifier that indexes the
// artifact URLs advertised by a custom registry's packument response, so a
// later request for one of those URLs can be resolved back to its package
// identity even when the URL itself does not follow the standard npm tarball
// convention. See artifactDiscoveryModifier for the shared discovery
// contract every ecosystem follows.
func npmMetadataDiscoveryModifier(ctx *proxy.RequestContext, artifacts *artifactIndex, registries registryConfigSet, registryName string, metadataURL *url.URL) proxy.ResponseModifierFunc {
	return artifactDiscoveryModifier(ctx, artifacts, registries, registryName, metadataURL,
		func(_ http.Header, body []byte) ([]advertisedArtifact, error) {
			return parseNpmMetadataArtifacts(metadataURL, body)
		})
}
