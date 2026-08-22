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

// parseNpmMetadataArtifacts extracts tarball URLs from an npm packument's
// "versions" map, supporting both full and abbreviated (install-v1) shapes.
// A malformed or inconsistent entry is skipped rather than failing the
// whole packument.
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

		// "versions" is keyed by the entry's own version string. A mismatch
		// means the entry's identity cannot be trusted.
		if entry.Version != "" && key != entry.Version {
			continue
		}

		name := entry.Name
		switch {
		case !identityFieldValid(name):
			// No usable name of its own: fall back to the packument's name.
			name = packument.Name
		case identityFieldValid(packument.Name) && name != packument.Name:
			// A valid name that disagrees with the packument's name is
			// inconsistent, like the mismatched version key above.
			continue
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

// identityFieldValid reports whether s is non-empty once trimmed and free of
// control characters. Shared by every ecosystem's metadata discovery.
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

// npmMetadataDiscoveryModifier indexes tarball URLs advertised by a
// packument response so a later request to a non-standard URL still
// resolves to its package identity. See artifactDiscoveryModifier for the
// shared discovery contract.
func npmMetadataDiscoveryModifier(ctx *proxy.RequestContext, artifacts *artifactIndex, registries registryConfigSet, registryName string, metadataURL *url.URL) proxy.ResponseModifierFunc {
	return artifactDiscoveryModifier(ctx, artifacts, registries, registryName, metadataURL,
		func(_ http.Header, body []byte) ([]advertisedArtifact, error) {
			return parseNpmMetadataArtifacts(metadataURL, body)
		})
}
