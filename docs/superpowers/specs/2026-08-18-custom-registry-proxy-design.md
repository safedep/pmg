# Custom npm and PyPI Registry Proxy Design

## Summary

PMG will support additional npm- and PyPI-compatible registry endpoints configured under `proxy.registries`. These registries are additive to PMG's built-in public registries.

The feature protects public packages served through enterprise mirrors, caching proxies, and custom registry deployments. It does not add analysis support for private packages. A package absent from SafeDep's analysis database retains the existing `NotFound` behavior and is allowed.

## Goals

- Analyze public npm and PyPI packages when they are downloaded through custom registry endpoints.
- Support registries hosted below arbitrary URL path prefixes.
- Support multiple registries and ecosystems on a shared hostname.
- Keep unrelated proxy traffic transparent.
- Preserve Host Observation logging for unconfigured hosts.
- Use one configuration model for wrapped package-manager commands and the persistent proxy.
- Leave room for endpoint-specific capabilities without adding speculative options.

## Non-goals

- Analyzing private or first-party packages absent from SafeDep's analysis database.
- Automatically discovering npm or PyPI registry configuration from package-manager configuration files or command-line flags.
- Automatically MITMing hosts found in registry metadata or redirects.
- Treating the proxy as a network allowlist.
- Supporting vendor-specific registry protocols that are not npm- or PyPI-compatible.
- Adding custom Go proxy configuration. Go continues to derive proxy endpoints from `GOPROXY`.
- Supporting implicit subdomain matching for custom registry endpoints.

## Configuration

```yaml
proxy:
  registries:
    - name: company-npm
      ecosystem: npm
      endpoints:
        - url: https://packages.company.internal/artifactory/api/npm/npm-virtual
        - url: https://downloads.company.internal/npm

    - name: company-pypi
      ecosystem: pypi
      endpoints:
        - url: https://packages.company.internal/artifactory/api/pypi/python/simple
```

Each registry has:

- `name`: a required, unique identifier used in diagnostics and available for future policy references.
- `ecosystem`: a required ecosystem identifier. Version one supports `npm` and `pypi`.
- `endpoints`: one or more endpoint objects.
- `endpoints[].url`: an absolute base URL defining a protected registry path prefix.

Endpoint entries are objects rather than strings so endpoint-specific capabilities can be added compatibly when a concrete need exists. No additional endpoint options are included in version one.

Configured registries extend the built-in registry definitions. They cannot replace or disable built-in protection.

## Endpoint Resolution

### Origin matching

An endpoint and request have the same origin when their normalized schemes, exact hostnames, and effective ports match. Custom endpoints do not implicitly match subdomains.

For HTTPS, the initial `CONNECT` request exposes only the hostname. PMG therefore decides whether to MITM at hostname granularity. Path matching happens after TLS interception and controls which decrypted requests enter registry processing. Requests elsewhere on the same configured hostname are forwarded unchanged.

### Segment-aware path matching

An endpoint URL represents a base URL, not one exact request URL. A request matches when its origin matches and either:

- its path equals the configured base path; or
- its path begins with the configured base path followed by `/`.

For example, `/artifactory/api/npm/team` matches `/artifactory/api/npm/team/lodash` but not `/artifactory/api/npm/team-backup`.

Trailing slashes are normalized. Query strings and fragments do not participate in matching. When multiple endpoints match, the endpoint with the longest path prefix wins. Identical endpoint prefixes assigned to multiple registries are invalid.

A root endpoint such as `https://npm.company.internal/` is valid for a dedicated host whose registry protocol begins at `/`. It causes all recognized registry paths on that host to enter the ecosystem parser.

### Parser input

PMG removes the matched endpoint's base path before ecosystem parsing. This lets existing protocol parsers operate on registry-relative paths even when a vendor mounts the registry below an arbitrary prefix.

Segment-aware matching identifies where the registry protocol starts; it does not adapt a nonstandard protocol. Content below the configured base must still follow the relevant npm or PyPI contract.

## Interception Behavior

PMG uses the following behavior for outbound requests:

1. A request to a configured hostname is eligible for hostname-level MITM.
2. A decrypted request matching a configured endpoint is routed to that registry's ecosystem interceptor.
3. The interceptor classifies recognized metadata and artifact requests and applies the relevant controls.
4. An unrecognized request on a configured hostname is forwarded unchanged.
5. A request to an unconfigured hostname is tunneled without MITM or analysis.
6. The existing Host Observation event records unconfigured hosts.

Custom configured hosts are considered known registry hosts for Host Observation purposes. Requests outside a matching endpoint path on that host remain transparent and do not become registry violations.

PMG never adds an interception target based on a metadata link or redirect. An artifact hosted on an unconfigured hostname is tunneled and is not analyzed. This coverage limitation must be documented. Organizations may explicitly add stable artifact-serving base URLs as endpoints when they want PMG to inspect them.

## Protocol Compatibility

### npm

Custom npm registries must provide npm-compatible package metadata. PMG supports the standard full and abbreviated packument forms used for installation, including package name, version entries, `dist.tarball`, and publish times needed for dependency cooldown.

PMG should use metadata to associate advertised tarball URLs with package coordinates when possible. This permits nonstandard artifact paths without requiring the path itself to encode the package name and version. Existing canonical npm tarball parsing remains a fallback when metadata correlation is unavailable.

Unknown metadata fields are ignored. Auxiliary endpoints such as authentication, search, audit, and health checks pass through when they are not recognized as package metadata or artifacts.

### PyPI

Custom PyPI registries must implement the Python Simple Repository API. PMG supports both the HTML representation and the PEP 691 JSON representation for artifact discovery. Relative file URLs are resolved against the metadata response URL.

Distribution filenames must carry enough standard Python package identity for PMG to determine the project and version. Existing wheel and source-distribution filename parsing remains available when metadata correlation is unavailable.

Dependency cooldown requires publish-time data. When a compatible client or registry response does not expose the required upload time, PMG retains its existing cooldown compatibility behavior rather than treating the registry as malformed.

### Identity and analysis

PMG analyzes an artifact only when it can reliably determine ecosystem, package name, and version. It does not guess package identity. Requests that cannot be classified as package artifacts pass through unchanged.

Analyzer failures and packages absent from the SafeDep analysis database retain existing behavior. In particular, private packages are not analyzed merely because their registry is configured. Documentation and diagnostics must state that custom registry support is intended for public packages served through mirrors or compatible registry proxies.

## Validation

Configuration loading must reject:

- duplicate or empty registry names;
- missing or unsupported ecosystems;
- registries without endpoints;
- empty, relative, or otherwise invalid endpoint URLs;
- URL schemes other than HTTP and HTTPS;
- URLs containing user information, query strings, or fragments;
- identical normalized endpoint prefixes assigned more than once.

Overlapping path prefixes are valid and use longest-prefix resolution. Different ecosystems may share one hostname when their endpoint paths do not conflict.

HTTP endpoints are accepted for compatibility with internal deployments, but PMG should warn that the upstream connection is not protected by TLS. HTTPS remains the documented recommendation.

Package-manager credentials remain in npm, Yarn, pnpm, pip, Poetry, uv, or their existing environment and configuration. PMG does not store, inject, or log registry credentials.

## Built-in Registries

Built-in npm and PyPI registries should use the same endpoint-resolution abstraction as custom registries. Their root endpoint paths preserve the current behavior of parsing recognized paths across the host.

Known hosts that intentionally bypass analysis, such as unsupported GitHub npm download hosts and Test PyPI, remain explicit tunnel-only knowledge for correct proxy behavior and Host Observation classification. Tunnel-only hosts are not exposed through the version-one custom registry schema.

The existing implicit subdomain behavior is independent of custom path-prefix support. Version one uses exact hostname matching for custom endpoints. Changing built-in subdomain semantics is outside this feature's scope and can be evaluated separately.

## Persistent and Per-command Proxy Modes

Custom registry configuration applies consistently to:

- package-manager commands wrapped by PMG; and
- the persistent proxy started by `pmg proxy start`.

Both assembly paths must receive the same validated registry definitions. The persistent proxy installs npm and PyPI interceptors simultaneously, while a wrapped command installs the interceptor for its package manager's ecosystem. Endpoint resolution and enforcement semantics remain identical.

## Documentation

User documentation must include:

- the public-package-only scope and private-package limitation;
- the additive relationship with built-in registries;
- how to obtain the package manager's effective registry or index base URL;
- how segment-aware path matching works;
- the distinction between hostname-level MITM and path-level registry processing;
- how multiple registries and ecosystems can share a hostname;
- when to add another endpoint for a stable artifact-serving URL;
- that unconfigured hosts are tunneled, not analyzed, and recorded as Host Observation events;
- that redirects and metadata links do not enroll hosts automatically;
- npm and PyPI protocol requirements;
- authentication ownership and credential-safety expectations;
- HTTP warnings and HTTPS recommendations;
- configuration validation errors and troubleshooting steps;
- complete npm and PyPI examples using enterprise-style path prefixes.

Documentation must avoid promising support for a vendor merely because its hostname can be configured. Compatibility depends on the registry serving standard npm metadata or the Python Simple Repository API beneath the configured base URL.

## Testing

This is a security-sensitive proxy-flow change and must extend the existing table-driven E2E framework in `test/proxye2e/` rather than introducing separate scaffolding.

Coverage must include:

- configuration decoding, normalization, and validation;
- exact hostname matching without implicit custom subdomain matching;
- segment-boundary and longest-prefix path matching;
- multiple ecosystems and repositories sharing a hostname;
- custom npm metadata and tarball allow/block flows;
- custom PyPI HTML and JSON Simple API distribution allow/block flows;
- dependency cooldown behavior on compatible custom metadata;
- unknown paths on configured hosts passing through;
- unknown hosts tunneling and producing Host Observation events;
- off-host artifact downloads remaining tunneled when not configured;
- explicitly configured stable artifact endpoints receiving analysis;
- persistent and per-command proxy assembly using the same registry definitions;
- built-in public registry behavior remaining unchanged;
- malformed configuration failing with actionable errors;
- private or analysis-database-absent packages retaining existing allow behavior.

## Future Extensions

The endpoint-object shape permits future additions without changing the registry list structure. Potential extensions must be driven by concrete use cases and may include endpoint compatibility profiles, custom trust roots, explicit subdomain behavior, or policy references.

Private-package analysis requires a separate design because the current analyzer identity does not include registry provenance or artifact content. It must not be implied by future endpoint configuration alone.
