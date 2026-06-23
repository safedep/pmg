package proxye2e

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

type NpmVersion struct {
	Version     string
	PublishedAt time.Time
	Tarball     []byte
}

type NpmPackage struct {
	Name          string
	DistTagLatest string
	Versions      []NpmVersion
}

type PypiVersion struct {
	Version     string
	PublishedAt time.Time
	Bytes       []byte
}

type PypiPackage struct {
	Name     string
	Versions []PypiVersion
}

type RecordedRequest struct {
	Host   string
	Method string
	Path   string
}

// Registry is an in-process stand-in for the npm and PyPI registries. The proxy
// upstream is redirected here, so it answers for every registry hostname and
// records each request for routing assertions.
type Registry struct {
	mu       sync.Mutex
	npm      map[string]NpmPackage
	pypi     map[string]PypiPackage
	requests []RecordedRequest
	server   *httptest.Server
}

func newRegistry() *Registry {
	r := &Registry{
		npm:  map[string]NpmPackage{},
		pypi: map[string]PypiPackage{},
	}
	r.server = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	return r
}

func (r *Registry) addr() string { return r.server.Listener.Addr().String() }

func (r *Registry) close() { r.server.Close() }

func (r *Registry) AddNpm(pkg NpmPackage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.npm[pkg.Name] = pkg
}

func (r *Registry) AddPypi(pkg PypiPackage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pypi[normalizePypiName(pkg.Name)] = pkg
}

// Requests returns every request the proxy forwarded upstream, in order.
func (r *Registry) Requests() []RecordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RecordedRequest, len(r.requests))
	copy(out, r.requests)
	return out
}

// DownloadedTarball reports whether a tarball for the given npm package version
// was fetched from the registry.
func (r *Registry) DownloadedTarball(name, version string) bool {
	want := fmt.Sprintf("/%s/-/%s-%s.tgz", name, name, version)
	for _, req := range r.Requests() {
		if req.Path == want {
			return true
		}
	}
	return false
}

func (r *Registry) serve(w http.ResponseWriter, req *http.Request) {
	host := hostOnly(req.Host)

	r.mu.Lock()
	r.requests = append(r.requests, RecordedRequest{Host: host, Method: req.Method, Path: req.URL.Path})
	r.mu.Unlock()

	switch host {
	case "registry.npmjs.org", "registry.yarnpkg.com":
		r.serveNpm(w, req)
	case "pypi.org":
		r.servePypiSimple(w, req)
	case "files.pythonhosted.org":
		r.servePypiFile(w, req)
	default:
		http.NotFound(w, req)
	}
}

func (r *Registry) serveNpm(w http.ResponseWriter, req *http.Request) {
	path := strings.Trim(req.URL.Path, "/")

	if strings.Contains(path, "/-/") {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("e2e-tarball"))
		return
	}

	r.mu.Lock()
	pkg, ok := r.npm[path]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buildPackument(pkg))
}

func (r *Registry) servePypiSimple(w http.ResponseWriter, req *http.Request) {
	name := strings.Trim(strings.TrimPrefix(req.URL.Path, "/simple/"), "/")

	r.mu.Lock()
	pkg, ok := r.pypi[normalizePypiName(name)]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}

	w.Header().Set("Content-Type", pypiSimpleContentType)
	_, _ = w.Write(buildPypiSimple(pkg))
}

func (r *Registry) servePypiFile(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write([]byte("e2e-wheel"))
}

const pypiSimpleContentType = "application/vnd.pypi.simple.v1+json"

func buildPackument(pkg NpmPackage) []byte {
	versions := map[string]any{}
	times := map[string]string{}
	for _, v := range pkg.Versions {
		versions[v.Version] = map[string]any{
			"name":    pkg.Name,
			"version": v.Version,
			"dist": map[string]any{
				"tarball": fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz", pkg.Name, pkg.Name, v.Version),
			},
		}
		times[v.Version] = v.PublishedAt.UTC().Format(time.RFC3339)
	}

	latest := pkg.DistTagLatest
	if latest == "" && len(pkg.Versions) > 0 {
		latest = pkg.Versions[len(pkg.Versions)-1].Version
	}

	doc := map[string]any{
		"name":      pkg.Name,
		"dist-tags": map[string]string{"latest": latest},
		"versions":  versions,
		"time":      times,
	}

	body, _ := json.Marshal(doc)
	return body
}

func buildPypiSimple(pkg PypiPackage) []byte {
	norm := normalizePypiName(pkg.Name)
	files := []map[string]any{}
	for _, v := range pkg.Versions {
		filename := fmt.Sprintf("%s-%s.tar.gz", norm, v.Version)
		files = append(files, map[string]any{
			"filename":    filename,
			"url":         fmt.Sprintf("https://files.pythonhosted.org/packages/source/%c/%s/%s", norm[0], norm, filename),
			"hashes":      map[string]string{},
			"upload-time": v.PublishedAt.UTC().Format(time.RFC3339Nano),
		})
	}

	doc := map[string]any{
		"meta":  map[string]any{"api-version": "1.0"},
		"name":  norm,
		"files": files,
	}

	body, _ := json.Marshal(doc)
	return body
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
