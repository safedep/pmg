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

func (d NpmDriver) FetchMetadata(name string) NpmMetadata {
	out := d.h.get(fmt.Sprintf("https://registry.npmjs.org/%s", name), nil)

	meta := NpmMetadata{Outcome: out}
	if out.Err == nil && out.StatusCode == 200 {
		if err := json.Unmarshal([]byte(out.Body), &meta); err != nil {
			meta.Outcome.Err = fmt.Errorf("failed to decode npm metadata for %s: %w", name, err)
		}
	}
	return meta
}

func (d NpmDriver) Download(name, version string) RequestOutcome {
	return d.h.get(fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz", name, name, version), nil)
}

// Install replays npm's resolve-then-download sequence: fetch the packument,
// pick the requested version (or dist-tags.latest), and download it only if it
// survived in the metadata the proxy returned.
func (d NpmDriver) Install(name, version string) ExecResult {
	res := ExecResult{}

	meta := d.FetchMetadata(name)
	res.add(meta.Outcome)

	target := version
	if target == "" {
		target = meta.DistTags["latest"]
	}

	if target != "" && meta.HasVersion(target) {
		res.add(d.Download(name, target))
	}

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

func (d PypiDriver) FetchSimple(name string) PypiSimple {
	out := d.h.get(
		fmt.Sprintf("https://pypi.org/simple/%s/", normalizePypiName(name)),
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
	res := ExecResult{}

	simple := d.FetchSimple(name)
	res.add(simple.Outcome)

	if f, ok := simple.fileForVersion(name, version); ok {
		res.add(d.Download(f.URL))
	}

	return res
}
