# Custom Registry Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add segment-aware custom npm and PyPI registry endpoints under `proxy.registries` so public packages served through enterprise mirrors receive PMG's existing analysis and cooldown controls.

**Architecture:** Validate additive registry definitions in `config`, then compile them with built-ins into ecosystem endpoint sets. TLS interception remains hostname-based, while decrypted requests use exact origin and longest segment-aware path-prefix matching; unmatched paths pass through and unconfigured hosts remain tunnelled and logged as Host Observations. npm packuments and PyPI Simple responses populate a registry-scoped artifact index so standard metadata can identify artifacts on non-canonical paths.

**Tech Stack:** Go, Viper/mapstructure, `elazarl/goproxy`, `testify`, `golang.org/x/net/html`, and the hermetic `test/proxye2e` framework.

---

## File Map

- Create `config/proxy_registry.go` and test: persisted types and validation.
- Modify `config/config.go`, `config/config.template.yml`, and template tests: expose the schema and defaults.
- Refactor `proxy/interceptors/registry_config.go` and test: endpoint compilation and URL matching.
- Create `proxy/interceptors/artifact_index.go` and test: metadata-to-artifact identity mapping.
- Create `proxy/interceptors/npm_metadata.go` and test; modify npm interceptor tests: custom npm handling.
- Create `proxy/interceptors/pypi_simple.go` and test; modify PyPI interceptor tests: custom PyPI handling.
- Modify interceptor factory/audit logger and both proxy assembly paths: consistent runtime wiring.
- Extend `test/proxye2e/`: security-sensitive end-to-end coverage.
- Modify `docs/proxy-mode.md` and `docs/persistent-proxy.md`: the user contract.

## Task 1: Add and Validate the Configuration Schema

**Files:**
- Create: `config/proxy_registry.go`
- Create: `config/proxy_registry_test.go`
- Modify: `config/config.go`
- Modify: `config/config_template_test.go`

- [ ] **Step 1: Write failing table-driven validation tests**

Cover valid npm/PyPI definitions, duplicate names, missing fields, unsupported ecosystems, empty endpoints, relative URLs, credentials, query/fragment components, unsupported schemes, and duplicate normalized endpoints.

```go
func TestValidateProxyRegistries(t *testing.T) {
	tests := []struct {
		name       string
		registries []ProxyRegistryConfig
		wantErr    string
	}{
		{
			name: "valid npm registry",
			registries: []ProxyRegistryConfig{{
				Name: "company-npm", Ecosystem: "npm",
				Endpoints: []ProxyRegistryEndpointConfig{{
					URL: "https://packages.example.test/artifactory/api/npm/team/",
				}},
			}},
		},
		{
			name: "duplicate name",
			registries: []ProxyRegistryConfig{
				{Name: "packages", Ecosystem: "npm", Endpoints: []ProxyRegistryEndpointConfig{{URL: "https://one.test/npm"}}},
				{Name: "packages", Ecosystem: "pypi", Endpoints: []ProxyRegistryEndpointConfig{{URL: "https://two.test/simple"}}},
			},
			wantErr: `duplicate proxy registry name "packages"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProxyRegistries(tt.registries)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
```

Add a Viper decode test proving `proxy.registries` maps into the typed list.

- [ ] **Step 2: Run tests and verify they fail**

```bash
go test ./config/ -run 'TestValidateProxyRegistries|TestProxyRegistriesConfig' -count=1
```

Expected: build failure because the types and validator do not exist.

- [ ] **Step 3: Implement types and validation**

```go
type ProxyRegistryConfig struct {
	Name      string                        `mapstructure:"name"`
	Ecosystem string                        `mapstructure:"ecosystem"`
	Endpoints []ProxyRegistryEndpointConfig `mapstructure:"endpoints"`
}

type ProxyRegistryEndpointConfig struct {
	URL string `mapstructure:"url"`
}

func ValidateProxyRegistries(registries []ProxyRegistryConfig) error {
	names := map[string]bool{}
	endpoints := map[string]string{}
	for index, registry := range registries {
		name := strings.TrimSpace(registry.Name)
		if name == "" {
			return fmt.Errorf("proxy.registries[%d].name is required", index)
		}
		if names[name] {
			return fmt.Errorf("duplicate proxy registry name %q", name)
		}
		names[name] = true
		if registry.Ecosystem != "npm" && registry.Ecosystem != "pypi" {
			return fmt.Errorf("proxy registry %q has unsupported ecosystem %q", name, registry.Ecosystem)
		}
		if len(registry.Endpoints) == 0 {
			return fmt.Errorf("proxy registry %q must define at least one endpoint", name)
		}
		for endpointIndex, endpoint := range registry.Endpoints {
			normalized, err := normalizeProxyRegistryURL(endpoint.URL)
			if err != nil {
				return fmt.Errorf("proxy registry %q endpoint %d: %w", name, endpointIndex, err)
			}
			if owner, exists := endpoints[normalized]; exists {
				return fmt.Errorf("proxy registry endpoint %q is already assigned to %q", normalized, owner)
			}
			endpoints[normalized] = name
		}
	}
	return nil
}
```

Add `Registries []ProxyRegistryConfig` to `ProxyConfig`. Make normalization require an absolute HTTP(S) URL, reject user info/query/fragment, normalize default ports and trailing slashes, and preserve meaningful escaped path segments. Validate `merged.Proxy.Registries` in `loadViperConfig` before activating the merged config.

- [ ] **Step 4: Run config tests**

```bash
go test ./config/ -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add config/config.go config/proxy_registry.go config/proxy_registry_test.go config/config_template_test.go
git commit -m "feat(config): add custom proxy registries"
```

## Task 2: Implement Segment-aware Endpoint Resolution

**Files:**
- Modify: `proxy/interceptors/registry_config.go`
- Modify: `proxy/interceptors/registry_config_test.go`

- [ ] **Step 1: Write failing resolver tests**

Test existing built-in subdomain behavior, exact custom hosts, exact and descendant paths, segment collision, scheme/effective-port matching, longest prefix, unmatched paths, and registry-relative path extraction.

```go
func TestRegistryConfigSetCustomEndpointPathMatch(t *testing.T) {
	set := registryConfigSet{entries: []*registryConfig{
		{Name: "short", Host: "packages.test", Scheme: "https", BasePath: "/npm", Parser: mockParser{}},
		{Name: "team", Host: "packages.test", Scheme: "https", BasePath: "/npm/team", Parser: mockParser{}},
	}}

	tests := []struct{ rawURL, wantName, wantPath string }{
		{"https://packages.test/npm/team/pkg", "team", "/pkg"},
		{"https://packages.test/npm/other", "short", "/other"},
		{"https://packages.test/npm/team-backup/pkg", "short", "/team-backup/pkg"},
		{"https://cdn.packages.test/npm/team/pkg", "", ""},
	}
	for _, tt := range tests {
		u, err := url.Parse(tt.rawURL)
		require.NoError(t, err)
		match := set.MatchURL(u)
		if tt.wantName == "" {
			assert.Nil(t, match)
			continue
		}
		require.NotNil(t, match)
		assert.Equal(t, tt.wantName, match.Config.Name)
		assert.Equal(t, tt.wantPath, match.RelativePath)
	}
}
```

- [ ] **Step 2: Run tests and verify they fail**

```bash
go test ./proxy/interceptors/ -run 'TestRegistryConfig(Set|Map)' -count=1
```

Expected: failure because URL-aware matching does not exist.

- [ ] **Step 3: Refactor to an endpoint set**

```go
type registryConfig struct {
	Name, Host, Scheme, Port, BasePath string
	MatchSubdomains, SupportedForAnalysis bool
	Parser registryURLParser
}

type registryMatch struct {
	Config       *registryConfig
	RelativePath string
}

type registryConfigSet struct {
	entries []*registryConfig
}

func (s registryConfigSet) ContainsHostname(hostname string) bool
func (s registryConfigSet) MatchURL(u *url.URL) *registryMatch
func (s registryConfigSet) KnownHosts() []string
```

Use `ContainsHostname` for CONNECT-time MITM and `MatchURL` after decryption. `MatchURL` compares normalized origins and accepts only `path == base` or `strings.HasPrefix(path, base+"/")`, selecting the longest base. Preserve subdomain matching only for current built-ins; custom entries are exact. Do not use `path.Clean` on escaped registry paths.

- [ ] **Step 4: Run tests**

```bash
go test ./proxy/interceptors/ -count=1
```

Expected: PASS, including existing built-in behavior.

- [ ] **Step 5: Commit**

```bash
git add proxy/interceptors/registry_config.go proxy/interceptors/registry_config_test.go
git commit -m "refactor(proxy): resolve registry endpoint prefixes"
```

## Task 3: Wire Custom Registries Through Both Proxy Modes

**Files:**
- Modify: `proxy/interceptors/factory.go`
- Create: `proxy/interceptors/factory_test.go`
- Modify: `proxy/interceptors/npm_registry.go`
- Modify: `proxy/interceptors/pypi_registry.go`
- Modify: `proxy/interceptors/audit_logger.go`
- Modify: `proxy/interceptors/audit_logger_test.go`
- Modify: `internal/flows/proxy_flow.go`
- Modify: `internal/proxyserver/server.go`
- Modify: `internal/proxyserver/server_test.go`

- [ ] **Step 1: Write failing factory and audit tests**

```go
func TestFactoryAddsCustomRegistryToMatchingEcosystem(t *testing.T) {
	ctx := InterceptorContext{Registries: []config.ProxyRegistryConfig{{
		Name: "company-npm", Ecosystem: "npm",
		Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.test/npm"}},
	}}}
	factory := NewInterceptorFactory(nil, nil, nil, nil, ctx)
	interceptor, err := factory.CreateInterceptor(packagev1.Ecosystem_ECOSYSTEM_NPM)
	require.NoError(t, err)
	decider := interceptor.(proxy.MITMDecider)
	assert.True(t, decider.ShouldMITM(&proxy.RequestContext{Hostname: "packages.test"}))
	assert.False(t, decider.ShouldMITM(&proxy.RequestContext{Hostname: "cdn.packages.test"}))
}
```

Also prove configured hosts are known to the audit logger while their subdomains and unrelated hosts remain observable.

- [ ] **Step 2: Run focused tests and verify they fail**

```bash
go test ./proxy/interceptors/ ./internal/proxyserver/ -run 'CustomRegistry|KnownRegistryHost' -count=1
```

Expected: failure because registries are not wired.

- [ ] **Step 3: Implement shared assembly**

Extend context:

```go
type InterceptorContext struct {
	PinnedVersions  map[string]string
	GoProxyBaseURLs map[string]string
	Registries      []config.ProxyRegistryConfig
}
```

Compile ecosystem-specific custom endpoints with the standard parser, configured base path, exact host matching, and analysis enabled. Emit one startup warning per configured plain-HTTP endpoint; do not warn per request. Pass `cfg.Config.Proxy.Registries` from both `internal/flows/proxy_flow.go` and `internal/proxyserver/server.go`.

Change the audit constructor to:

```go
func NewAuditLoggerInterceptor(customRegistryHosts []string) *AuditLoggerInterceptor
```

Configured exact hosts join existing built-in knowledge. Do not suppress observations for custom subdomains.

- [ ] **Step 4: Run assembly tests**

```bash
go test ./proxy/interceptors/ ./internal/flows/ ./internal/proxyserver/ -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add proxy/interceptors/factory.go proxy/interceptors/factory_test.go proxy/interceptors/npm_registry.go proxy/interceptors/pypi_registry.go proxy/interceptors/audit_logger.go proxy/interceptors/audit_logger_test.go internal/flows/proxy_flow.go internal/proxyserver/server.go internal/proxyserver/server_test.go
git commit -m "feat(proxy): wire custom registry endpoints"
```

## Task 4: Add a Registry-scoped Artifact Index

**Files:**
- Create: `proxy/interceptors/artifact_index.go`
- Create: `proxy/interceptors/artifact_index_test.go`

- [ ] **Step 1: Write failing tests**

Cover absolute/relative links, fragment removal, query preservation for signed URLs, registry isolation, bounded eviction/expiry, concurrent access, and response-modifier order.

```go
func TestArtifactIndexResolvesAdvertisedURL(t *testing.T) {
	index := newArtifactIndex()
	base, err := url.Parse("https://packages.test/simple/demo/")
	require.NoError(t, err)
	require.NoError(t, index.Add("company-pypi", base, "../../files/demo-1.0.whl#sha256=abc", artifactIdentity{Name: "demo", Version: "1.0"}))

	requestURL, err := url.Parse("https://packages.test/files/demo-1.0.whl")
	require.NoError(t, err)
	identity, ok := index.Get("company-pypi", requestURL)
	assert.True(t, ok)
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "1.0"}, identity)
}
```

- [ ] **Step 2: Run tests and verify they fail**

```bash
go test ./proxy/interceptors/ -run 'TestArtifactIndex|TestChainResponseModifiers' -count=1
```

Expected: build failure.

- [ ] **Step 3: Implement the index and modifier chain**

```go
type artifactIdentity struct {
	Name, Version string
}

type artifactIndex struct {
	mu      sync.RWMutex
	entries map[string]artifactIndexEntry
	limit   int
	ttl     time.Duration
	now     func() time.Time
}

func (i *artifactIndex) Add(registry string, base *url.URL, ref string, identity artifactIdentity) error
func (i *artifactIndex) Get(registry string, requestURL *url.URL) (artifactIdentity, bool)
```

Resolve references against metadata URLs, remove fragments, preserve queries, normalize origins, and include registry name in keys. Bound the index for the persistent proxy: expire entries after 15 minutes and cap it at 10,000 entries, pruning expired entries before evicting the oldest live entry. Inject `now` in tests so expiry is deterministic. Add `chainResponseModifiers`; discovery runs before cooldown so it reads the upstream representation.

- [ ] **Step 4: Run tests with the race detector**

```bash
go test -race ./proxy/interceptors/ -run 'TestArtifactIndex|TestChainResponseModifiers' -count=1
```

Expected: PASS with no races.

- [ ] **Step 5: Commit**

```bash
git add proxy/interceptors/artifact_index.go proxy/interceptors/artifact_index_test.go
git commit -m "feat(proxy): index registry artifact URLs"
```

## Task 5: Support Custom npm Metadata and Artifacts

**Files:**
- Create: `proxy/interceptors/npm_metadata.go`
- Create: `proxy/interceptors/npm_metadata_test.go`
- Modify: `proxy/interceptors/npm_registry.go`
- Modify: `proxy/interceptors/npm_registry_test.go`

- [ ] **Step 1: Write failing npm tests**

Test full/abbreviated packuments, relative/absolute tarballs, scoped packages, custom prefix stripping, unknown-path pass-through, canonical fallback, opaque mapped artifacts, and cooldown composition.

```go
func TestNpmMetadataArtifacts(t *testing.T) {
	body := []byte(`{"name":"demo","versions":{"1.2.3":{"name":"demo","version":"1.2.3","dist":{"tarball":"../../download/opaque?id=42"}}}}`)
	base, err := url.Parse("https://packages.test/npm/demo")
	require.NoError(t, err)
	artifacts, err := parseNpmMetadataArtifacts(base, body)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)
	assert.Equal(t, "https://packages.test/download/opaque?id=42", artifacts[0].URL.String())
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "1.2.3"}, artifacts[0].Identity)
}
```

- [ ] **Step 2: Run tests and verify they fail**

```bash
go test ./proxy/interceptors/ -run 'TestNpm(MetadataArtifacts|RegistryInterceptor_Custom)' -count=1
```

Expected: failure because metadata discovery and prefix routing are missing.

- [ ] **Step 3: Implement metadata extraction**

Decode only standard `name`, `versions.*.name`, `versions.*.version`, and `versions.*.dist.tarball`. Require non-empty identity fields and resolve tarball references against the metadata URL. Ignore unrelated fields.

- [ ] **Step 4: Integrate npm routing and artifact lookup**

Resolve the full request URL through the endpoint set. If no path matches, return `ActionAllow`. Check the registry-scoped artifact index before canonical path parsing; mapped artifacts reuse `fastAllow`, `analyzePackage`, and `handleAnalysisResult`. For metadata, register discovery and chain it before cooldown modification.

```go
match := i.domains.MatchURL(ctx.URL)
if match == nil {
	return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, nil
}
if identity, ok := i.artifacts.Get(match.Config.Name, ctx.URL); ok {
	return i.handleArtifact(ctx, identity.Name, identity.Version)
}
pkgInfo, err := match.Config.Parser.ParseURL(match.RelativePath)
```

- [ ] **Step 5: Run npm tests**

```bash
go test ./proxy/interceptors/ -run 'Npm' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add proxy/interceptors/npm_metadata.go proxy/interceptors/npm_metadata_test.go proxy/interceptors/npm_registry.go proxy/interceptors/npm_registry_test.go
git commit -m "feat(proxy): analyze custom npm registries"
```

## Task 6: Support Custom PyPI Simple APIs and Artifacts

**Files:**
- Create: `proxy/interceptors/pypi_simple.go`
- Create: `proxy/interceptors/pypi_simple_test.go`
- Modify: `proxy/interceptors/pypi_registry.go`
- Modify: `proxy/interceptors/pypi_registry_test.go`

- [ ] **Step 1: Write failing PyPI tests**

Cover PEP 691 JSON, PEP 503 HTML, relative/absolute links, fragments, normalized names, custom `/simple` prefix stripping, separate download prefix, opaque mapped artifacts, filename fallback, unknown paths, and cooldown composition.

```go
func TestParsePypiSimpleJSONArtifacts(t *testing.T) {
	body := []byte(`{"name":"demo","files":[{"filename":"demo-1.2.3-py3-none-any.whl","url":"../../files/opaque/42#sha256=abc"}]}`)
	base, err := url.Parse("https://packages.test/python/simple/demo/")
	require.NoError(t, err)
	artifacts, err := parsePypiSimpleArtifacts(base, pypiSimpleAPIContentType, body)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)
	assert.Equal(t, artifactIdentity{Name: "demo", Version: "1.2.3"}, artifacts[0].Identity)
}
```

- [ ] **Step 2: Run tests and verify they fail**

```bash
go test ./proxy/interceptors/ -run 'Test(ParsePypiSimple|PypiRegistryInterceptor_Custom)' -count=1
```

Expected: failure because discovery and custom routing are missing.

- [ ] **Step 3: Implement Simple API discovery**

For JSON decode `name` and `files[].filename/url`. For HTML use `golang.org/x/net/html` to read anchor `href` values and the final decoded path segment. Parse wheel/sdist identity through `parseFilename`, resolve relative references, and select formats with `mime.ParseMediaType`.

```go
func parsePypiSimpleArtifacts(base *url.URL, contentType string, body []byte) ([]advertisedArtifact, error)
```

- [ ] **Step 4: Integrate PyPI routing and artifact lookup**

Treat one project-name segment below a configured `/simple` base as metadata, retain existing `/simple` and `/pypi` parsing when the configured base is higher, and recognize supported distribution filenames as fallback artifacts. Use the artifact index before path fallback and chain discovery before cooldown. Do not guess arbitrary paths.

- [ ] **Step 5: Run PyPI tests**

```bash
go test ./proxy/interceptors/ -run 'Pypi|PyPI' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add proxy/interceptors/pypi_simple.go proxy/interceptors/pypi_simple_test.go proxy/interceptors/pypi_registry.go proxy/interceptors/pypi_registry_test.go
git commit -m "feat(proxy): analyze custom PyPI registries"
```

## Task 7: Add Hermetic Proxy E2E Coverage

**Files:**
- Modify: `test/proxye2e/harness.go`
- Modify: `test/proxye2e/registry.go`
- Modify: `test/proxye2e/proxye2e_test.go`

- [ ] **Step 1: Pass case configuration into the harness**

Reset `rc.Config.Proxy.Registries` in `applyConfig` so cases cannot leak registry definitions. After `RunCases` applies `TestCase.Config`, have `New` pass `config.Get().Config.Proxy.Registries` to `InterceptorContext`. Extend the in-process registry to serve custom npm/PyPI prefixes, a separate stable download prefix, an unrelated path, and an off-host artifact URL. Keep all upstream connections redirected by the existing `UpstreamDialContext`.

- [ ] **Step 2: Add failing `TestCase` entries**

Use the existing `Config`/`Setup`/`Exec`/`Assert` framework for custom npm clean/block/cooldown, custom PyPI JSON and HTML flows, shared-host ecosystems, unknown path pass-through, custom subdomain tunneling, off-host tunneling, explicitly configured download analysis, and built-in regressions.

```go
{
	Name: "custom npm prefix blocks malware",
	Config: func(rc *config.RuntimeConfig) {
		rc.Config.Proxy.Registries = []config.ProxyRegistryConfig{{
			Name: "company-npm", Ecosystem: "npm",
			Endpoints: []config.ProxyRegistryEndpointConfig{{URL: "https://packages.example.test/npm/team"}},
		}}
	},
	Setup: func(h *Harness) {
		h.Registry.AddNpm(NpmPackage{Name: "evil", DistTagLatest: "1.0.0", Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
		h.Analyzer.SetNpm("evil", "1.0.0", VerifiedMalware())
	},
	Exec: func(h *Harness) ExecResult {
		return h.Npm().InstallFrom("https://packages.example.test/npm/team", "evil", "1.0.0")
	},
	Assert: func(t *testing.T, h *Harness, result ExecResult) {
		assert.True(t, result.Blocked())
		assert.Equal(t, 1, h.Analyzer.AnalyzedCount("evil", "1.0.0"))
	},
}
```

- [ ] **Step 3: Run new E2E cases and verify they fail**

```bash
go test ./test/proxye2e/ -run 'TestProxyFlow_(Custom|Npm|Pypi)' -count=1
```

Expected: new cases fail until the mock paths and drivers are connected.

- [ ] **Step 4: Complete only reusable harness changes**

Add driver methods only for reusable install operations; use `Harness.RawClient` for edge cases. Record both host and path so assertions distinguish tunnelling from analysis.

- [ ] **Step 5: Run all proxy E2E tests**

```bash
go test ./test/proxye2e/ -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add test/proxye2e/harness.go test/proxye2e/registry.go test/proxye2e/proxye2e_test.go
git commit -m "test(proxy): cover custom registries end to end"
```

## Task 8: Document Configuration and Compatibility

**Files:**
- Modify: `config/config.template.yml`
- Modify: `config/config_template_test.go`
- Modify: `docs/proxy-mode.md`
- Modify: `docs/persistent-proxy.md`

- [ ] **Step 1: Add failing template assertions**

Assert the embedded template decodes to an empty registry list and contains a commented example without enabling a fake endpoint.

- [ ] **Step 2: Replace the existing registry sketch carefully**

Preserve unrelated user changes in `config/config.template.yml` and use:

```yaml
  # Additional npm/PyPI-compatible endpoints serving public packages through
  # an internal mirror or registry proxy. Private packages are not analyzed.
  registries: []
  # registries:
  #   - name: company-npm
  #     ecosystem: npm
  #     endpoints:
  #       - url: https://packages.example.com/artifactory/api/npm/npm-virtual
```

- [ ] **Step 3: Document the complete user contract**

In `docs/proxy-mode.md`, document additive built-ins, exact custom hosts, segment-aware matching, positive/negative prefix examples, hostname MITM versus path processing, longest-prefix shared hosts, npm/PyPI standards, stable download endpoints, unknown-host Host Observations, no redirect enrollment, package-manager-owned credentials, HTTP warnings, public-only analysis, and troubleshooting for shallow prefixes/unconfigured artifacts. Include concrete discovery commands (`npm config get registry`, scope-specific npm config, and `pip config debug`/the effective `index-url`) while explaining that PMG does not discover those settings automatically.

In `docs/persistent-proxy.md`, state that the daemon loads the same registry list at startup and must restart after changes.

- [ ] **Step 4: Run checks**

```bash
go test ./config/ -run 'TestTemplate' -count=1
git diff --check
```

Expected: PASS with no whitespace errors.

- [ ] **Step 5: Commit**

```bash
git add config/config.template.yml config/config_template_test.go docs/proxy-mode.md docs/persistent-proxy.md
git commit -m "docs: explain custom registry proxying"
```

## Task 9: Full Verification and Review

**Files:**
- Review all files changed in Tasks 1-8.

- [ ] **Step 1: Format changed Go files**

Run `gofmt -w` on every changed `.go` file listed by `git diff --name-only -- '*.go'`.

- [ ] **Step 2: Run focused race tests**

```bash
go test -race ./proxy/interceptors/ ./test/proxye2e/ -count=1
```

Expected: PASS with no endpoint-resolution or artifact-index races.

- [ ] **Step 3: Run the complete test suite**

```bash
go test ./... -count=1
```

Expected: PASS.

- [ ] **Step 4: Build every package**

```bash
go build ./...
```

Expected: exit code 0.

- [ ] **Step 5: Inspect final state**

```bash
git diff --check
git status --short
git diff --stat origin/main...HEAD
```

Expected: no whitespace errors; only intentional custom-registry changes and pre-existing user-owned working-tree files are present.

- [ ] **Step 6: Request code review**

Invoke `superpowers:requesting-code-review` and focus on accidental MITM expansion, path/escaping bypasses, cross-registry artifact contamination, private-package claims, persistent/per-command drift, and proxy E2E gaps.

- [ ] **Step 7: Apply review fixes and repeat verification**

Commit focused review fixes, then repeat Steps 2-5 before claiming completion.
