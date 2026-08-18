package proxye2e

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/module"
)

type NpmVersion struct {
	Version     string
	PublishedAt time.Time
	Tarball     []byte

	// TarballURL overrides the canonical "/-/name-version.tgz" dist URL a
	// custom npm mount would otherwise generate, so a test can advertise an
	// opaque artifact reference (or an off-host one) that only resolves
	// through metadata discovery rather than URL parsing.
	TarballURL string
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

	// FileURL overrides the canonical hash-directory file URL a custom pypi
	// mount would otherwise generate, mirroring NpmVersion.TarballURL.
	FileURL string
}

type PypiPackage struct {
	Name     string
	Versions []PypiVersion
}

// mount is a host+basePath a custom registry test registers with the mock: a
// npm/PyPI ecosystem interceptor strips this same prefix before parsing, so
// the registry mirrors that matching to decide how to serve a request. A
// registry can register more than one mount on the same host (a metadata
// prefix and a separate download prefix, or two registries sharing a host at
// different depths); matchMount picks the longest matching basePath, the
// same longest-base-wins rule the interceptor's own registry matching uses.
type mount struct {
	host     string
	basePath string
}

func normalizeMountBasePath(basePath string) string {
	basePath = strings.TrimSuffix(basePath, "/")
	if basePath != "" && !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	return basePath
}

func matchMount(mounts []mount, host, path string) (mount, bool) {
	var best mount
	found := false
	for _, m := range mounts {
		if m.host != host {
			continue
		}
		if m.basePath != "" && path != m.basePath && !strings.HasPrefix(path, m.basePath+"/") {
			continue
		}
		if !found || len(m.basePath) > len(best.basePath) {
			best = m
			found = true
		}
	}
	return best, found
}

type GoVersion struct {
	Version     string
	PublishedAt time.Time
}

type GoModule struct {
	Path     string
	Versions []GoVersion
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
	mu         sync.Mutex
	npm        map[string]NpmPackage
	pypi       map[string]PypiPackage
	gomod      map[string]GoModule
	npmMounts  []mount
	pypiMounts []mount
	requests   []RecordedRequest
	server     *httptest.Server
	goServer   *httptest.Server
}

func newRegistry() *Registry {
	r := &Registry{
		npm:   map[string]NpmPackage{},
		pypi:  map[string]PypiPackage{},
		gomod: map[string]GoModule{},
	}
	r.server = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	// Plain-HTTP GOPROXY endpoint for the interceptor's out-of-band .info
	// fetches, which go straight to the upstream base URL rather than through
	// the proxy under test. It also serves the /goproxy base path used to
	// exercise GOPROXY path-prefix handling.
	r.goServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.record(req)
		r.serveGoWithOptionalPrefix(w, req)
	}))
	return r
}

func (r *Registry) addr() string { return r.server.Listener.Addr().String() }

func (r *Registry) goBaseURL() string { return r.goServer.URL }

func (r *Registry) close() {
	r.server.Close()
	r.goServer.Close()
}

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

func (r *Registry) AddGoModule(mod GoModule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gomod[mod.Path] = mod
}

// AddCustomNpm registers a custom npm mount point: requests to host under
// basePath are served packument/tarball style, exactly like the built-in
// registry.npmjs.org host, using packages registered via AddNpm. A registry
// can register more than one mount on the same host, e.g. a metadata prefix
// and a separate download prefix.
func (r *Registry) AddCustomNpm(host, basePath string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.npmMounts = append(r.npmMounts, mount{host: host, basePath: normalizeMountBasePath(basePath)})
}

// AddCustomPypi registers a custom PyPI Simple API mount point: requests to
// host under basePath are served project-index style using packages
// registered via AddPypi, as PEP 691 JSON by default or PEP 503 HTML when the
// request's Accept header names the HTML media type.
func (r *Registry) AddCustomPypi(host, basePath string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pypiMounts = append(r.pypiMounts, mount{host: host, basePath: normalizeMountBasePath(basePath)})
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

// Requested reports whether the registry received a request for the exact
// host and path, regardless of the registry's built-in naming conventions.
// Custom registry mounts can nest a package under an arbitrary base path, so
// this is the general-purpose counterpart to DownloadedTarball/DownloadedGoZip
// for asserting exactly which request did or did not reach the registry.
func (r *Registry) Requested(host, path string) bool {
	for _, req := range r.Requests() {
		if req.Host == host && req.Path == path {
			return true
		}
	}
	return false
}

func (r *Registry) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, RecordedRequest{Host: hostOnly(req.Host), Method: req.Method, Path: req.URL.Path})
}

func (r *Registry) serve(w http.ResponseWriter, req *http.Request) {
	r.record(req)

	host := hostOnly(req.Host)

	r.mu.Lock()
	npmMount, npmOK := matchMount(r.npmMounts, host, req.URL.Path)
	pypiMount, pypiOK := matchMount(r.pypiMounts, host, req.URL.Path)
	r.mu.Unlock()

	switch {
	case npmOK:
		r.serveCustomNpm(w, req, npmMount)
		return
	case pypiOK:
		r.serveCustomPypi(w, req, pypiMount)
		return
	}

	switch host {
	case "registry.npmjs.org", "registry.yarnpkg.com":
		r.serveNpm(w, req)
	case "pypi.org":
		r.servePypiSimple(w, req)
	case "files.pythonhosted.org":
		r.servePypiFile(w, req)
	case "proxy.golang.org", "corp.example.com":
		r.serveGoWithOptionalPrefix(w, req)
	default:
		http.NotFound(w, req)
	}
}

// serveGoWithOptionalPrefix serves the GOPROXY protocol either at the root
// (proxy.golang.org) or under the /goproxy base path (corp.example.com and
// the corp base URL of the plain-HTTP go server).
func (r *Registry) serveGoWithOptionalPrefix(w http.ResponseWriter, req *http.Request) {
	if strings.HasPrefix(req.URL.Path, "/goproxy/") {
		http.StripPrefix("/goproxy", http.HandlerFunc(r.serveGo)).ServeHTTP(w, req)
		return
	}
	r.serveGo(w, req)
}

// DownloadedGoZip reports whether the module zip for the given path and
// version was fetched from the registry.
func (r *Registry) DownloadedGoZip(modulePath, version string) bool {
	want := "/" + goEscapePath(modulePath) + "/@v/" + goEscapeVersion(version) + ".zip"
	for _, req := range r.Requests() {
		if req.Path == want {
			return true
		}
	}
	return false
}

// serveGo implements a minimal GOPROXY protocol endpoint: .info (with publish
// time), .mod and .zip per registered module version, plus /sumdb/* which the
// real proxy serves for checksum-database lookups.
func (r *Registry) serveGo(w http.ResponseWriter, req *http.Request) {
	p := strings.TrimPrefix(req.URL.Path, "/")

	if strings.HasPrefix(p, "sumdb/") {
		_, _ = w.Write([]byte("e2e-sumdb"))
		return
	}

	escapedPath, versionPart, found := strings.Cut(p, "/@v/")
	if !found {
		http.NotFound(w, req)
		return
	}

	modulePath, err := module.UnescapePath(escapedPath)
	if err != nil {
		http.NotFound(w, req)
		return
	}

	r.mu.Lock()
	mod, ok := r.gomod[modulePath]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}

	ext := path.Ext(versionPart)
	version, err := module.UnescapeVersion(strings.TrimSuffix(versionPart, ext))
	if err != nil {
		http.NotFound(w, req)
		return
	}

	var published time.Time
	versionFound := false
	for _, v := range mod.Versions {
		if v.Version == version {
			published = v.PublishedAt
			versionFound = true
			break
		}
	}
	if !versionFound {
		http.NotFound(w, req)
		return
	}

	switch ext {
	case ".info":
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(map[string]string{
			"Version": version,
			"Time":    published.UTC().Format(time.RFC3339),
		})
		_, _ = w.Write(body)
	case ".mod":
		_, _ = fmt.Fprintf(w, "module %s\n", modulePath)
	case ".zip":
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write([]byte("e2e-module-zip"))
	default:
		http.NotFound(w, req)
	}
}

func goEscapePath(p string) string {
	escaped, err := module.EscapePath(p)
	if err != nil {
		return p
	}
	return escaped
}

func goEscapeVersion(v string) string {
	escaped, err := module.EscapeVersion(v)
	if err != nil {
		return v
	}
	return escaped
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
	_, _ = w.Write(buildPackument(pkg, "https://registry.npmjs.org"))
}

// serveCustomNpm serves a request under a custom npm mount. It mirrors
// serveNpm's conventions relative to the mount's own basePath: a canonical
// "/-/name-version.tgz" path always returns tarball bytes regardless of
// package registration (matching the interceptor's unconditional canonical
// parsing), and anything else is looked up as a packument by name.
func (r *Registry) serveCustomNpm(w http.ResponseWriter, req *http.Request, m mount) {
	relative := strings.Trim(strings.TrimPrefix(req.URL.Path, m.basePath), "/")

	if strings.Contains(relative, "/-/") {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("e2e-tarball"))
		return
	}

	r.mu.Lock()
	pkg, ok := r.npm[relative]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buildPackument(pkg, "https://"+m.host+m.basePath))
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
	_, _ = w.Write(buildPypiSimple(pkg, pypiFilesBase))
}

// serveCustomPypi serves a request under a custom PyPI Simple API mount. A
// last path segment shaped like a distribution filename always returns file
// bytes unconditionally, at any depth, mirroring pypiCustomParser's canonical
// filename-at-any-depth rule; otherwise the first segment is looked up as a
// project's Simple API index, rendered as PEP 691 JSON or PEP 503 HTML
// depending on the request's Accept header.
func (r *Registry) serveCustomPypi(w http.ResponseWriter, req *http.Request, m mount) {
	relative := strings.Trim(strings.TrimPrefix(req.URL.Path, m.basePath), "/")
	segments := strings.Split(relative, "/")
	lastSegment := segments[len(segments)-1]

	if isPypiDistFilename(lastSegment) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("e2e-wheel"))
		return
	}

	r.mu.Lock()
	pkg, ok := r.pypi[normalizePypiName(segments[0])]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}

	filesBase := "https://" + m.host + m.basePath
	if wantsHTML(req) {
		w.Header().Set("Content-Type", pypiSimpleHTMLContentType)
		_, _ = w.Write(buildPypiSimpleHTML(pkg, filesBase))
		return
	}

	w.Header().Set("Content-Type", pypiSimpleContentType)
	_, _ = w.Write(buildPypiSimple(pkg, filesBase))
}

func (r *Registry) servePypiFile(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write([]byte("e2e-wheel"))
}

const pypiSimpleContentType = "application/vnd.pypi.simple.v1+json"

// pypiSimpleHTMLContentType is the PEP 691 HTML media type served for a
// custom PyPI mount's PEP 503 responses. Plain "text/html" is also treated as
// wanting HTML, since that is what most real Simple API servers send.
const pypiSimpleHTMLContentType = "application/vnd.pypi.simple.v1+html"

const pypiFilesBase = "https://files.pythonhosted.org/packages/source"

func wantsHTML(req *http.Request) bool {
	return strings.Contains(req.Header.Get("Accept"), "html")
}

func isPypiDistFilename(name string) bool {
	for _, ext := range []string{".whl", ".tar.gz", ".tar.bz2", ".tgz", ".zip"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func buildPackument(pkg NpmPackage, tarballBase string) []byte {
	versions := map[string]any{}
	times := map[string]string{}
	for _, v := range pkg.Versions {
		tarball := v.TarballURL
		if tarball == "" {
			tarball = fmt.Sprintf("%s/%s/-/%s-%s.tgz", tarballBase, pkg.Name, pkg.Name, v.Version)
		}
		versions[v.Version] = map[string]any{
			"name":    pkg.Name,
			"version": v.Version,
			"dist": map[string]any{
				"tarball": tarball,
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

func buildPypiSimple(pkg PypiPackage, filesBase string) []byte {
	norm := normalizePypiName(pkg.Name)
	files := []map[string]any{}
	for _, v := range pkg.Versions {
		filename := fmt.Sprintf("%s-%s.tar.gz", norm, v.Version)
		files = append(files, map[string]any{
			"filename":    filename,
			"url":         pypiFileURL(v.FileURL, filesBase, norm, filename),
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

// buildPypiSimpleHTML renders the same project index as buildPypiSimple in
// PEP 503 HTML shape: one anchor per version, whose href is the file's
// identity-bearing URL. Discovery derives an artifact's identity from the
// href's own final path segment, never from the anchor text, so the text
// content here is only diagnostic.
func buildPypiSimpleHTML(pkg PypiPackage, filesBase string) []byte {
	norm := normalizePypiName(pkg.Name)
	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html><body>\n")
	for _, v := range pkg.Versions {
		filename := fmt.Sprintf("%s-%s.tar.gz", norm, v.Version)
		url := pypiFileURL(v.FileURL, filesBase, norm, filename)
		b.WriteString(fmt.Sprintf("<a href=%q>%s</a><br/>\n", url, filename))
	}
	b.WriteString("</body></html>")
	return []byte(b.String())
}

// pypiFileURL returns override if set, otherwise the canonical hash-directory
// URL real PyPI uses for files.pythonhosted.org, rooted at filesBase.
func pypiFileURL(override, filesBase, norm, filename string) string {
	if override != "" {
		return override
	}
	return fmt.Sprintf("%s/%c/%s/%s", filesBase, norm[0], norm, filename)
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
