package proxye2e

import (
	"encoding/json"
	"fmt"
	"strings"
)

type RequestOutcome struct {
	URL        string
	StatusCode int
	Blocked    bool
	Body       string
	Err        error
}

// ExecResult is the aggregate of requests an install driver issued.
type ExecResult struct {
	Requests []RequestOutcome
}

func (e *ExecResult) add(o RequestOutcome) { e.Requests = append(e.Requests, o) }

// Blocked reports whether any request was blocked by the proxy.
func (e ExecResult) Blocked() bool {
	for _, r := range e.Requests {
		if r.Blocked {
			return true
		}
	}
	return false
}

type NpmDriver struct{ h *Harness }

type NpmMetadata struct {
	Outcome  RequestOutcome
	DistTags map[string]string          `json:"dist-tags"`
	Versions map[string]json.RawMessage `json:"versions"`
	Time     map[string]string          `json:"time"`
}

func (m NpmMetadata) HasVersion(v string) bool {
	_, ok := m.Versions[v]
	return ok
}

const npmRegistryBaseURL = "https://registry.npmjs.org"

func (d NpmDriver) FetchMetadata(name string) NpmMetadata {
	return d.FetchMetadataFrom(npmRegistryBaseURL, name)
}

// FetchMetadataFrom fetches a packument from an arbitrary base URL, e.g. a
// custom registry's configured endpoint.
func (d NpmDriver) FetchMetadataFrom(baseURL, name string) NpmMetadata {
	out := d.h.get(fmt.Sprintf("%s/%s", baseURL, name), nil)

	meta := NpmMetadata{Outcome: out}
	if out.Err == nil && out.StatusCode == 200 {
		if err := json.Unmarshal([]byte(out.Body), &meta); err != nil {
			meta.Outcome.Err = fmt.Errorf("failed to decode npm metadata for %s: %w", name, err)
		}
	}
	return meta
}

func (d NpmDriver) Download(name, version string) RequestOutcome {
	return d.DownloadFrom(npmRegistryBaseURL, name, version)
}

// DownloadFrom fetches a canonical "/-/name-version.tgz" tarball relative to
// an arbitrary base URL, e.g. a custom registry's configured endpoint.
func (d NpmDriver) DownloadFrom(baseURL, name, version string) RequestOutcome {
	return d.h.get(fmt.Sprintf("%s/%s/-/%s-%s.tgz", baseURL, name, name, version), nil)
}

// Install replays npm's resolve-then-download sequence: fetch the packument,
// pick the requested version (or dist-tags.latest), and download it only if it
// survived in the metadata the proxy returned.
func (d NpmDriver) Install(name, version string) ExecResult {
	return d.InstallFrom(npmRegistryBaseURL, name, version)
}

// InstallFrom replays Install's resolve-then-download sequence against an
// arbitrary base URL, e.g. a custom registry's configured endpoint.
func (d NpmDriver) InstallFrom(baseURL, name, version string) ExecResult {
	res := ExecResult{}

	meta := d.FetchMetadataFrom(baseURL, name)
	res.add(meta.Outcome)

	target := version
	if target == "" {
		target = meta.DistTags["latest"]
	}

	if target != "" && meta.HasVersion(target) {
		res.add(d.DownloadFrom(baseURL, name, target))
	}

	return res
}

type GoDriver struct{ h *Harness }

func (d GoDriver) goProxyURL(modulePath, version, ext string) string {
	return fmt.Sprintf("https://proxy.golang.org/%s/@v/%s%s",
		goEscapePath(modulePath), goEscapeVersion(version), ext)
}

// DownloadZipVia fetches a module zip from an arbitrary GOPROXY base URL,
// e.g. a corporate proxy serving under a path prefix.
func (d GoDriver) DownloadZipVia(baseURL, modulePath, version string) RequestOutcome {
	return d.h.get(fmt.Sprintf("%s/%s/@v/%s.zip",
		baseURL, goEscapePath(modulePath), goEscapeVersion(version)), nil)
}

func (d GoDriver) FetchInfo(modulePath, version string) RequestOutcome {
	return d.h.get(d.goProxyURL(modulePath, version, ".info"), nil)
}

func (d GoDriver) FetchMod(modulePath, version string) RequestOutcome {
	return d.h.get(d.goProxyURL(modulePath, version, ".mod"), nil)
}

func (d GoDriver) DownloadZip(modulePath, version string) RequestOutcome {
	return d.h.get(d.goProxyURL(modulePath, version, ".zip"), nil)
}

// Install replays go's fetch sequence for a resolved module version:
// .info, then .mod, then the .zip source archive.
func (d GoDriver) Install(modulePath, version string) ExecResult {
	res := ExecResult{}

	info := d.FetchInfo(modulePath, version)
	res.add(info)
	if info.Err != nil || info.StatusCode != 200 {
		return res
	}

	res.add(d.FetchMod(modulePath, version))
	res.add(d.DownloadZip(modulePath, version))
	return res
}

type PypiDriver struct{ h *Harness }

type PypiSimpleFile struct {
	Filename   string `json:"filename"`
	URL        string `json:"url"`
	UploadTime string `json:"upload-time"`
}

type PypiSimple struct {
	Outcome RequestOutcome
	Files   []PypiSimpleFile `json:"files"`
}

func (s PypiSimple) fileForVersion(name, version string) (PypiSimpleFile, bool) {
	prefix := fmt.Sprintf("%s-%s.", normalizePypiName(name), version)
	for _, f := range s.Files {
		if strings.HasPrefix(f.Filename, prefix) {
			return f, true
		}
	}
	return PypiSimpleFile{}, false
}

func (s PypiSimple) HasVersion(name, version string) bool {
	_, ok := s.fileForVersion(name, version)
	return ok
}

const pypiSimpleBaseURL = "https://pypi.org/simple"

func (d PypiDriver) FetchSimple(name string) PypiSimple {
	return d.FetchSimpleFrom(pypiSimpleBaseURL, name)
}

// FetchSimpleFrom fetches a Simple API project index from an arbitrary base
// URL as PEP 691 JSON, e.g. a custom registry's configured endpoint.
func (d PypiDriver) FetchSimpleFrom(baseURL, name string) PypiSimple {
	out := d.h.get(
		fmt.Sprintf("%s/%s/", baseURL, normalizePypiName(name)),
		map[string]string{"Accept": pypiSimpleContentType},
	)

	simple := PypiSimple{Outcome: out}
	if out.Err == nil && out.StatusCode == 200 {
		if err := json.Unmarshal([]byte(out.Body), &simple); err != nil {
			simple.Outcome.Err = fmt.Errorf("failed to decode PyPI simple index for %s: %w", name, err)
		}
	}
	return simple
}

func (d PypiDriver) Download(fileURL string) RequestOutcome {
	return d.h.get(fileURL, nil)
}

// Install replays pip's resolve-then-download sequence over the PEP 691 Simple
// API: fetch the index, then download the requested version's file only if it
// survived cooldown stripping.
func (d PypiDriver) Install(name, version string) ExecResult {
	return d.InstallFrom(pypiSimpleBaseURL, name, version)
}

// InstallFrom replays Install's resolve-then-download sequence against an
// arbitrary Simple API base URL, e.g. a custom registry's configured endpoint.
func (d PypiDriver) InstallFrom(baseURL, name, version string) ExecResult {
	res := ExecResult{}

	simple := d.FetchSimpleFrom(baseURL, name)
	res.add(simple.Outcome)

	if f, ok := simple.fileForVersion(name, version); ok {
		res.add(d.Download(f.URL))
	}

	return res
}
