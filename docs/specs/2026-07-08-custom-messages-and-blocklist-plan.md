# Custom Block Messages and Package Blocklist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-control custom block messages (`dependency_cooldown.message`, `malware.message`) and a `blocked_packages` blocklist to PMG config, enforced as a fast-path block in both proxy and guard flows.

**Architecture:** Config gains a `BlockedPackage` type sharing PURL parse/match machinery with `TrustedPackage` via an embedded `purlRef`. The proxy's `fastAllow` gate becomes `policyGate` with precedence insecure → blocked → trusted, blocking before any analyzer call. The guard flow scans the resolved graph against the blocklist before trusted-skip/analysis. Custom messages are appended on every surface that renders the corresponding block: report sections, silent-mode report output (fixed as part of this work — today it prints nothing), and proxy 403 bodies.

**Tech Stack:** Go, viper/mapstructure config, testify, hermetic proxy E2E framework (`test/proxye2e`).

**Spec:** `docs/specs/2026-07-08-custom-messages-and-blocklist-spec.md`

## Global Constraints

- Precedence for a concrete package version: `InsecureInstallation` allow → `blocked_packages` block → `trusted_packages` allow → remaining controls.
- Blocklist matching mirrors trusted_packages exactly: PURL without version blocks ALL versions; PURL with version blocks only that version.
- Blocklist blocks are hard blocks: no confirmation prompt, no analyzer/cache/circuit-breaker involvement.
- Custom messages are appended, never replace built-in output; unset/empty message = current behavior exactly.
- No YAML key changes to existing config; full backward compatibility, no migration.
- No metadata stripping for blocked versions.
- Repo style: testify assert/require, table-driven tests, no unnecessary comments, check `fmt.Fprintf` errors.
- Do NOT add `Co-Authored-By` lines to commits.
- Run `go build ./...` and `go test ./... -count=1` before each commit.

---

### Task 1: Config — `purlRef` machinery, `BlockedPackage`, `MalwareConfig`, messages, template

**Files:**
- Create: `config/packageref.go`
- Create: `config/blocked.go`
- Create: `config/blocked_test.go`
- Modify: `config/config.go` (Config struct ~line 71–114, `TrustedPackage` ~line 288, `DefaultConfig` ~line 461, `initConfig` ~line 599)
- Modify: `config/trusted.go`
- Modify: `config/config.template.yml`
- Modify: `config/config_template_test.go`
- Modify: `test/proxye2e/runner.go` (rename `PreprocessTrustedPackages` call)
- Modify: `proxy/interceptors/base_registry_test.go:21,24` (rename `PreprocessTrustedPackages` call)

**Interfaces:**
- Consumes: existing `pb.NewPurlPackageVersion`, `config.Get()`.
- Produces (later tasks rely on these exact signatures):
  - `config.FindBlockedPackage(pv *packagev1.PackageVersion) (BlockedPackage, bool)`
  - `config.FindBlockedPackageRef(ecosystem packagev1.Ecosystem, name, version string) (BlockedPackage, bool)`
  - `config.PreprocessPackageRefs(cfg *Config) error` (replaces `PreprocessTrustedPackages`)
  - `Config.BlockedPackages []BlockedPackage`, `Config.Malware MalwareConfig{Message string}`, `DependencyCooldownConfig.Message string`
  - `BlockedPackage{Purl, Reason string}` (plus embedded unexported `purlRef`)

- [ ] **Step 1: Write the failing test**

Create `config/blocked_test.go`:

```go
package config

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setBlockedPackagesForTest(t *testing.T, pkgs []BlockedPackage) {
	t.Helper()
	orig := Get().Config.BlockedPackages
	Get().Config.BlockedPackages = pkgs
	require.NoError(t, PreprocessPackageRefs(&Get().Config))
	t.Cleanup(func() {
		Get().Config.BlockedPackages = orig
		assert.NoError(t, PreprocessPackageRefs(&Get().Config))
	})
}

func TestFindBlockedPackageRef(t *testing.T) {
	cases := []struct {
		name        string
		blocked     []BlockedPackage
		ecosystem   packagev1.Ecosystem
		pkg         string
		version     string
		wantBlocked bool
		wantReason  string
	}{
		{
			name:        "version-less entry blocks any version",
			blocked:     []BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "deprecated"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkg:         "left-pad",
			version:     "1.3.0",
			wantBlocked: true,
			wantReason:  "deprecated",
		},
		{
			name:        "version-pinned entry blocks that version",
			blocked:     []BlockedPackage{{Purl: "pkg:npm/lodash@4.17.20", Reason: "CVE"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkg:         "lodash",
			version:     "4.17.20",
			wantBlocked: true,
			wantReason:  "CVE",
		},
		{
			name:        "version-pinned entry does not block other versions",
			blocked:     []BlockedPackage{{Purl: "pkg:npm/lodash@4.17.20", Reason: "CVE"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkg:         "lodash",
			version:     "4.17.21",
			wantBlocked: false,
		},
		{
			name:        "different ecosystem does not match",
			blocked:     []BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "deprecated"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_PYPI,
			pkg:         "left-pad",
			version:     "1.3.0",
			wantBlocked: false,
		},
		{
			name:        "invalid purl never matches",
			blocked:     []BlockedPackage{{Purl: "not-a-purl", Reason: "x"}},
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkg:         "not-a-purl",
			version:     "1.0.0",
			wantBlocked: false,
		},
		{
			name:        "empty blocklist matches nothing",
			blocked:     nil,
			ecosystem:   packagev1.Ecosystem_ECOSYSTEM_NPM,
			pkg:         "anything",
			version:     "1.0.0",
			wantBlocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setBlockedPackagesForTest(t, tc.blocked)

			got, ok := FindBlockedPackageRef(tc.ecosystem, tc.pkg, tc.version)
			assert.Equal(t, tc.wantBlocked, ok)
			if tc.wantBlocked {
				assert.Equal(t, tc.wantReason, got.Reason)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./config/ -run TestFindBlockedPackageRef -v -count=1`
Expected: FAIL to compile — `undefined: BlockedPackage`, `undefined: PreprocessPackageRefs`, `undefined: FindBlockedPackageRef`.

- [ ] **Step 3: Implement the machinery and types**

Create `config/packageref.go`:

```go
package config

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/api/pb"
	"github.com/safedep/dry/log"
)

// purlRef is the pre-parsed form of a PURL list entry (trusted_packages,
// dependency_cooldown.skip, blocked_packages). Parsing happens once at config
// load; entries with an invalid PURL are marked unparsed and never match.
type purlRef struct {
	parsed    bool
	ecosystem packagev1.Ecosystem
	name      string
	version   string
}

func (r *purlRef) parseFrom(purl string) {
	parsedPurl, err := pb.NewPurlPackageVersion(purl)
	if err != nil {
		log.Warnf("Failed to parse package PURL: %s: %v", purl, err)
		r.parsed = false
		return
	}

	r.parsed = true
	r.ecosystem = parsedPurl.Ecosystem()
	r.name = parsedPurl.Name()
	r.version = parsedPurl.Version()
}

// matches reports whether the ref matches a package version. A version-less
// ref matches every version of the package.
func (r purlRef) matches(pv *packagev1.PackageVersion) bool {
	if !r.parsed || pv == nil {
		return false
	}
	if r.ecosystem != pv.GetPackage().GetEcosystem() {
		return false
	}
	if r.name != pv.GetPackage().GetName() {
		return false
	}
	if r.version != "" && r.version != pv.GetVersion() {
		return false
	}
	return true
}
```

In `config/config.go`, replace the `TrustedPackage` struct (line ~288) and add `BlockedPackage` next to it. `TrustedPackage` and `BlockedPackage` stay distinct types (so either can grow control-specific fields later); the shared machinery is the embedded `purlRef`:

```go
type TrustedPackage struct {
	Purl   string `mapstructure:"purl"`
	Reason string `mapstructure:"reason"`

	purlRef
}

// BlockedPackage is an entry in the blocked_packages blocklist. A matching
// package version is always blocked; the blocklist wins over trusted_packages.
type BlockedPackage struct {
	Purl   string `mapstructure:"purl"`
	Reason string `mapstructure:"reason"`

	purlRef
}
```

Note: mapstructure and yaml both skip the unexported embedded `purlRef`, so serialization is unchanged. Existing in-package access to `v.parsed`/`v.ecosystem`/`v.name`/`v.version` (e.g. `cooldownSkip` in `trusted.go`) keeps working via field promotion.

Add to the `Config` struct (after `TrustedPackages`):

```go
	// BlockedPackages is an explicit blocklist. A matching package version is
	// always blocked — the blocklist wins over trusted_packages. Only insecure
	// installation mode bypasses it.
	BlockedPackages []BlockedPackage `mapstructure:"blocked_packages"`

	// Malware configures the malicious-package control.
	Malware MalwareConfig `mapstructure:"malware"`
```

Add the section type (near `DependencyCooldownConfig`):

```go
// MalwareConfig configures the malicious-package control.
type MalwareConfig struct {
	// Message is an optional org-specific message appended to every
	// malicious-package block output.
	Message string `mapstructure:"message"`
}
```

Add to `DependencyCooldownConfig`:

```go
	// Message is an optional org-specific message appended to every
	// cooldown block output.
	Message string `mapstructure:"message"`
```

In `DefaultConfig()` add `BlockedPackages: []BlockedPackage{},` after `TrustedPackages`.

In `config/trusted.go`, delete `preprocessTrustedPackageList` and the parse body of `preprocessTrustedPackages`; replace with:

```go
// PreprocessPackageRefs pre-parses all PURL strings in the trusted, cooldown
// skip, and blocked package lists. Exported for use in cross-package tests that
// install synthetic configs without going through Load.
func PreprocessPackageRefs(cfg *Config) error {
	return preprocessPackageRefs(cfg)
}

// preprocessPackageRefs parses the PURL of each list entry in place, populating
// the pre-parsed purlRef. This is called once during config load to avoid
// repeated parsing at match time. Invalid PURLs are logged but not fatal.
func preprocessPackageRefs(cfg *Config) error {
	for i := range cfg.TrustedPackages {
		cfg.TrustedPackages[i].parseFrom(cfg.TrustedPackages[i].Purl)
	}
	for i := range cfg.DependencyCooldown.Skip {
		cfg.DependencyCooldown.Skip[i].parseFrom(cfg.DependencyCooldown.Skip[i].Purl)
	}
	for i := range cfg.BlockedPackages {
		cfg.BlockedPackages[i].parseFrom(cfg.BlockedPackages[i].Purl)
	}
	return nil
}
```

Remove the old `PreprocessTrustedPackages`/`preprocessTrustedPackages` names entirely. Update the call in `config/config.go` `initConfig()` (line ~599) to `preprocessPackageRefs(&globalConfig.Config)`, and simplify `isTrustedPackageVersion` to use the shared matcher:

```go
func isTrustedPackageVersion(trustedPackages []TrustedPackage, pkgVersion *packagev1.PackageVersion) bool {
	for _, v := range trustedPackages {
		if v.matches(pkgVersion) {
			return true
		}
	}
	return false
}
```

Update the two external callers of the old name:
- `test/proxye2e/runner.go:67`: `config.PreprocessTrustedPackages` → `config.PreprocessPackageRefs`
- `proxy/interceptors/base_registry_test.go:21,24`: `pmgconfig.PreprocessTrustedPackages` → `pmgconfig.PreprocessPackageRefs`

Create `config/blocked.go`:

```go
package config

import (
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

// FindBlockedPackage returns the blocked_packages entry matching a package
// version. Matching mirrors trusted_packages: a version-less entry blocks
// every version, a version-pinned entry blocks only that version.
func FindBlockedPackage(pkgVersion *packagev1.PackageVersion) (BlockedPackage, bool) {
	for _, b := range Get().Config.BlockedPackages {
		if b.matches(pkgVersion) {
			return b, true
		}
	}
	return BlockedPackage{}, false
}

// FindBlockedPackageRef is FindBlockedPackage for a loose ecosystem/name/version reference.
func FindBlockedPackageRef(ecosystem packagev1.Ecosystem, name, version string) (BlockedPackage, bool) {
	return FindBlockedPackage(&packagev1.PackageVersion{
		Package: &packagev1.Package{Ecosystem: ecosystem, Name: name},
		Version: version,
	})
}
```

- [ ] **Step 4: Update the config template and template tests**

In `config/config.template.yml`, add `message` to the `dependency_cooldown` section (after `days: 5`):

```yaml
  # Optional message appended to the block output whenever installation is
  # blocked by the dependency cooldown. Useful for org deployments to point
  # developers at internal policy docs or an exemption process. Example:
  #   message: "Blocked by ACME security policy. Request an exemption at go/pmg-exceptions"
  message: ""
```

Add two new top-level sections after the `dependency_cooldown` block:

```yaml
# Malicious package control settings.
malware:
  # Optional message appended to the block output whenever a malicious package
  # is blocked. Useful for org deployments to point developers at internal
  # security contacts. Example:
  #   message: "Malicious package blocked by ACME SecOps. Report false positives in #security-help"
  message: ""

# Blocked packages are always blocked by PMG, regardless of malware analysis
# verdicts. Matching mirrors trusted_packages: a PURL without a version blocks
# ALL versions of the package; a PURL with a version blocks only that version.
#
# The blocklist wins over trusted_packages: a package on both lists is blocked.
# The reason is shown to the user when the package is blocked.
# Example:
#   blocked_packages:
#     - purl: pkg:npm/left-pad
#       reason: "Deprecated internally; use String.prototype.padStart"
#     - purl: pkg:npm/lodash@4.17.20
#       reason: "CVE-2021-23337 - upgrade to >=4.17.21"
blocked_packages: []
```

In `config/config_template_test.go`, extend `TestTemplateParsesAsYAML` (after the `TrustedPackages` assertion):

```go
	assert.Empty(t, cfg.BlockedPackages)
	assert.Empty(t, cfg.Malware.Message)
	assert.Empty(t, cfg.DependencyCooldown.Message)
```

Extend `TestTemplateMatchesDefaults` (after the `DependencyCooldown` assertions):

```go
	assert.Equal(t, def.DependencyCooldown.Message, parsed.DependencyCooldown.Message, "dependency_cooldown.message mismatch")
	assert.Equal(t, def.Malware.Message, parsed.Malware.Message, "malware.message mismatch")
	assert.Equal(t, len(def.BlockedPackages), len(parsed.BlockedPackages), "blocked_packages mismatch")
```

- [ ] **Step 5: Run tests and build**

Run: `go build ./... && go test ./config/ ./test/proxye2e/ ./proxy/interceptors/ -count=1`
Expected: PASS (all existing trusted/cooldown-skip tests must stay green).

- [ ] **Step 6: Commit**

```bash
git add config/ test/proxye2e/runner.go proxy/interceptors/base_registry_test.go
git commit -m "feat(config): add blocked_packages list and custom block messages"
```

---

### Task 2: Blocklist model and audit event

**Files:**
- Create: `internal/models/blocklist.go`
- Modify: `internal/audit/event.go` (EventType consts, ~line 49)
- Modify: `internal/audit/audit.go` (new Log function)
- Modify: `internal/audit/cloud_translate.go` (~line 12 switch)
- Modify: `internal/audit/cloud_translate_test.go`

**Interfaces:**
- Consumes: existing `logEvent`, `newPackageDecisionEvent`, `global.recordBlocked()`.
- Produces (later tasks rely on these exact signatures):
  - `models.BlocklistBlock{Name, Version, Reason string}`
  - `audit.LogBlocklistBlocked(pv *packagev1.PackageVersion, reason string)`
  - `audit.EventTypeBlocklistBlocked EventType = "package_blocklist_blocked"`

- [ ] **Step 1: Write the failing test**

Add to `internal/audit/cloud_translate_test.go` (reuse the file's existing `testSink` var and imports; follow `TestTranslateMalwareBlocked` at line 16 for the assertion style):

```go
func TestTranslateBlocklistBlocked(t *testing.T) {
	pv := &packagev1.PackageVersion{
		Package: &packagev1.Package{Name: "left-pad", Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
		Version: "1.0.0",
	}

	events := testSink.translateToPmgEvents(AuditEvent{
		Type:           EventTypeBlocklistBlocked,
		PackageVersion: pv,
		Details:        map[string]any{"reason": "deprecated internally"},
	})

	require.Len(t, events, 1)
	assert.Equal(t, controltowerv1.PmgEventType_PMG_EVENT_TYPE_PACKAGE_DECISION, events[0].GetEventType())
	assert.Equal(t, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_BLOCKED, events[0].GetPackageDecision().GetAction())
	assert.Equal(t, "left-pad", events[0].GetPackageDecision().GetPackageVersion().GetPackage().GetName())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -run TestTranslateBlocklistBlocked -v -count=1`
Expected: FAIL to compile — `undefined: EventTypeBlocklistBlocked`.

- [ ] **Step 3: Implement model, event type, log function, translation**

Create `internal/models/blocklist.go`:

```go
package models

// BlocklistBlock records a package blocked by the blocked_packages policy.
type BlocklistBlock struct {
	Name    string
	Version string
	Reason  string
}
```

In `internal/audit/event.go`, add to the EventType const block:

```go
	EventTypeBlocklistBlocked      EventType = "package_blocklist_blocked"
```

In `internal/audit/audit.go`, add after `LogMalwareBlocked`:

```go
// LogBlocklistBlocked records that a package was blocked by the
// blocked_packages policy, independent of any malware verdict.
func LogBlocklistBlocked(pv *packagev1.PackageVersion, reason string) {
	logEvent(AuditEvent{
		Type:           EventTypeBlocklistBlocked,
		Message:        fmt.Sprintf("Blocked installation of blocklisted package: %s@%s", pkgName(pv), pkgVersion(pv)),
		PackageVersion: pv,
		Details: map[string]any{
			"reason": reason,
		},
	})

	if global != nil {
		global.recordBlocked()
	}
}
```

In `internal/audit/cloud_translate.go`, add to the switch (after the `EventTypeMalwareBlocked` case):

```go
	case EventTypeBlocklistBlocked:
		return []*controltowerv1.PmgEvent{newPackageDecisionEvent(event, controltowerv1.PmgPackageAction_PMG_PACKAGE_ACTION_BLOCKED)}
```

- [ ] **Step 4: Run tests**

Run: `go build ./... && go test ./internal/audit/ ./internal/models/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/models/blocklist.go internal/audit/
git commit -m "feat(audit): add package_blocklist_blocked event and blocklist model"
```

---

### Task 3: Proxy fast-path policy gate

**Files:**
- Modify: `proxy/interceptors/base_registry.go` (rename `fastAllow` → `policyGate`, ~line 74–102)
- Modify: `proxy/interceptors/stats.go` (new record/get methods, `AnalysisStats` field)
- Modify: `proxy/interceptors/npm_registry.go:126`, `pypi_registry.go:150`, `go_registry.go:193` (call-site rename)
- Modify: `proxy/interceptors/base_registry_test.go` (rename existing tests, add new)
- Modify: `test/proxye2e/harness.go` (expose blocklist blocks, after `CooldownBlocks` ~line 193)

**Interfaces:**
- Consumes: `config.FindBlockedPackageRef` (Task 1), `audit.LogBlocklistBlocked`, `models.BlocklistBlock` (Task 2).
- Produces (later tasks rely on these exact signatures):
  - `(b *baseRegistryInterceptor) policyGate(ctx *proxy.RequestContext, ecosystem packagev1.Ecosystem, name, version string) (*proxy.InterceptorResponse, bool)`
  - `(c *AnalysisStatsCollector) RecordBlocklistBlocked(name, version, reason string)`
  - `(c *AnalysisStatsCollector) GetBlocklistBlocks() []models.BlocklistBlock`
  - `AnalysisStats.BlocklistBlockedCount int`
  - `(h *Harness) BlocklistBlocks() []models.BlocklistBlock` (proxye2e)

- [ ] **Step 1: Write the failing tests**

In `proxy/interceptors/base_registry_test.go`, rename the three `TestFastAllow_*` functions to `TestPolicyGate_TrustedReturnsAllow`, `TestPolicyGate_UntrustedReturnsFalse`, `TestPolicyGate_InsecureReturnsAllow` and change `b.fastAllow(` to `b.policyGate(` in each. Add a helper and new tests:

```go
func setBlockedPackagesForTest(t *testing.T, pkgs []pmgconfig.BlockedPackage) {
	t.Helper()
	orig := pmgconfig.Get().Config.BlockedPackages
	pmgconfig.Get().Config.BlockedPackages = pkgs
	require.NoError(t, pmgconfig.PreprocessPackageRefs(&pmgconfig.Get().Config))
	t.Cleanup(func() {
		pmgconfig.Get().Config.BlockedPackages = orig
		assert.NoError(t, pmgconfig.PreprocessPackageRefs(&pmgconfig.Get().Config))
	})
}

func TestPolicyGate_BlocklistedReturnsBlock(t *testing.T) {
	setBlockedPackagesForTest(t, []pmgconfig.BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "deprecated internally"}})

	stats := NewAnalysisStatsCollector()
	b := &baseRegistryInterceptor{statsCollector: stats}
	ctx := makeTestRequestContext("https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz")

	resp, ok := b.policyGate(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "left-pad", "1.0.0")
	require.True(t, ok)
	assert.Equal(t, proxy.ActionBlock, resp.Action)
	assert.Equal(t, http.StatusForbidden, resp.BlockCode)
	assert.Contains(t, resp.BlockMessage, "blocked_packages")
	assert.Contains(t, resp.BlockMessage, "deprecated internally")
	assert.Equal(t, 1, stats.GetStats().BlocklistBlockedCount)

	blocks := stats.GetBlocklistBlocks()
	require.Len(t, blocks, 1)
	assert.Equal(t, "left-pad", blocks[0].Name)
	assert.Equal(t, "1.0.0", blocks[0].Version)
	assert.Equal(t, "deprecated internally", blocks[0].Reason)
}

func TestPolicyGate_BlockWinsOverTrust(t *testing.T) {
	setTrustedPackagesForTest(t, []pmgconfig.TrustedPackage{{Purl: "pkg:npm/left-pad"}})
	setBlockedPackagesForTest(t, []pmgconfig.BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "banned"}})

	b := &baseRegistryInterceptor{}
	ctx := makeTestRequestContext("https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz")

	resp, ok := b.policyGate(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "left-pad", "1.0.0")
	require.True(t, ok)
	assert.Equal(t, proxy.ActionBlock, resp.Action)
}

func TestPolicyGate_InsecureWinsOverBlocklist(t *testing.T) {
	setBlockedPackagesForTest(t, []pmgconfig.BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "banned"}})

	orig := pmgconfig.Get().InsecureInstallation
	pmgconfig.Get().InsecureInstallation = true
	t.Cleanup(func() { pmgconfig.Get().InsecureInstallation = orig })

	b := &baseRegistryInterceptor{}
	ctx := makeTestRequestContext("https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz")

	resp, ok := b.policyGate(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "left-pad", "1.0.0")
	require.True(t, ok)
	assert.Equal(t, proxy.ActionAllow, resp.Action)
}

func TestPolicyGate_BlocklistReasonOmittedWhenEmpty(t *testing.T) {
	setBlockedPackagesForTest(t, []pmgconfig.BlockedPackage{{Purl: "pkg:npm/left-pad"}})

	b := &baseRegistryInterceptor{}
	ctx := makeTestRequestContext("https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz")

	resp, ok := b.policyGate(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "left-pad", "1.0.0")
	require.True(t, ok)
	assert.NotContains(t, resp.BlockMessage, "Reason:")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./proxy/interceptors/ -run TestPolicyGate -v -count=1`
Expected: FAIL to compile — `undefined: b.policyGate`, `undefined: RecordBlocklistBlocked`.

- [ ] **Step 3: Implement the gate and stats**

In `proxy/interceptors/stats.go`, add `BlocklistBlockedCount int` to `AnalysisStats`, `blocklistBlocks []models.BlocklistBlock` to `AnalysisStatsCollector`, and:

```go
// RecordBlocklistBlocked records a package blocked by the blocked_packages policy.
func (c *AnalysisStatsCollector) RecordBlocklistBlocked(name, version, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.TotalAnalyzed++
	c.stats.BlockedCount++
	c.stats.BlocklistBlockedCount++
	c.blocklistBlocks = append(c.blocklistBlocks, models.BlocklistBlock{
		Name:    name,
		Version: version,
		Reason:  reason,
	})
}

// GetBlocklistBlocks returns all packages blocked by the blocked_packages policy.
func (c *AnalysisStatsCollector) GetBlocklistBlocks() []models.BlocklistBlock {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]models.BlocklistBlock, len(c.blocklistBlocks))
	copy(result, c.blocklistBlocks)
	return result
}
```

In `proxy/interceptors/base_registry.go`, rename `fastAllow` to `policyGate`, update its doc comment, and insert the blocklist branch between the insecure and trusted checks:

```go
// policyGate short-circuits the request when a policy decides the outcome
// before any analysis runs. Precedence: insecure-installation mode (explicit
// bypass-everything escape hatch), then the blocked_packages blocklist (an
// explicit block beats trust), then trusted_packages (waives every control).
// It returns (response, true) when it handled the request; (nil, false) when
// the request must proceed to analysis.
func (b *baseRegistryInterceptor) policyGate(
	ctx *proxy.RequestContext,
	ecosystem packagev1.Ecosystem,
	name, version string,
) (*proxy.InterceptorResponse, bool) {
	pkgVersion := &packagev1.PackageVersion{
		Package: &packagev1.Package{Ecosystem: ecosystem, Name: name},
		Version: version,
	}

	if config.Get().InsecureInstallation {
		log.Debugf("[%s] Skipping insecure installation", ctx.RequestID)
		audit.LogInstallInsecureBypass(pkgVersion)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, true
	}

	if blocked, ok := config.FindBlockedPackageRef(ecosystem, name, version); ok {
		log.Warnf("[%s] Blocking blocklisted package %s/%s@%s", ctx.RequestID, ecosystem.String(), name, version)
		audit.LogBlocklistBlocked(pkgVersion, blocked.Reason)

		if b.statsCollector != nil {
			b.statsCollector.RecordBlocklistBlocked(name, version, blocked.Reason)
		}

		return &proxy.InterceptorResponse{
			Action:       proxy.ActionBlock,
			BlockCode:    http.StatusForbidden,
			BlockMessage: blocklistBlockMessage(ecosystem, name, version, blocked.Reason),
		}, true
	}

	if config.IsTrustedPackageRef(ecosystem, name, version) {
		log.Debugf("[%s] Skipping trusted package: %s/%s@%s", ctx.RequestID, ecosystem.String(), name, version)
		audit.LogInstallTrustedAllowed(pkgVersion)
		return &proxy.InterceptorResponse{Action: proxy.ActionAllow}, true
	}

	return nil, false
}

// blocklistBlockMessage builds the 403 body for a blocklist hit. The label is
// distinct from the malware block message so a policy block is never mistaken
// for a malware verdict.
func blocklistBlockMessage(ecosystem packagev1.Ecosystem, name, version, reason string) string {
	message := fmt.Sprintf("Package blocked by PMG policy (blocked_packages): %s/%s@%s",
		ecosystem.String(), name, version)
	if reason != "" {
		message += fmt.Sprintf("\n\nReason: %s", reason)
	}
	return message
}
```

Rename the call sites: `npm_registry.go:126`, `pypi_registry.go:150`, `go_registry.go:193` — `i.fastAllow(` → `i.policyGate(`.

In `test/proxye2e/harness.go`, add after `CooldownBlocks()`:

```go
func (h *Harness) BlocklistBlocks() []models.BlocklistBlock { return h.stats.GetBlocklistBlocks() }
```

- [ ] **Step 4: Run tests**

Run: `go build ./... && go test ./proxy/interceptors/ ./test/proxye2e/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add proxy/interceptors/ test/proxye2e/harness.go
git commit -m "feat(proxy): block blocklisted packages in the policy gate before analysis"
```

---

### Task 4: Guard flow blocklist enforcement

**Files:**
- Modify: `guard/guard.go` (`GuardResult` ~line 85, `Run` ~line 190, `handleManifestInstallation` ~line 428)
- Modify: `guard/guard_test.go`

**Interfaces:**
- Consumes: `config.FindBlockedPackage`, `audit.LogBlocklistBlocked`, `models.BlocklistBlock`, `config.PreprocessPackageRefs`.
- Produces: `GuardResult.BlocklistBlocked []models.BlocklistBlock` (consumed by Task 5's common_flow plumbing).

- [ ] **Step 1: Write the failing test**

Add to `guard/guard_test.go` (uses a local recording analyzer so no network and so we can prove analysis never ran; note the import additions: `pmgconfig "github.com/safedep/pmg/config"`, `"github.com/safedep/pmg/internal/models"`, `"github.com/stretchr/testify/require"`):

```go
type recordingAnalyzer struct {
	calls int
}

func (a *recordingAnalyzer) Name() string { return "recording" }

func (a *recordingAnalyzer) Analyze(_ context.Context, pv *packagev1.PackageVersion) (*analyzer.PackageVersionAnalysisResult, error) {
	a.calls++
	return &analyzer.PackageVersionAnalysisResult{PackageVersion: pv, Action: analyzer.ActionAllow}, nil
}

func TestGuardBlocklistedPackage(t *testing.T) {
	rc := pmgconfig.Get()
	savedBlocked := rc.Config.BlockedPackages
	savedTrusted := rc.Config.TrustedPackages
	t.Cleanup(func() {
		rc.Config.BlockedPackages = savedBlocked
		rc.Config.TrustedPackages = savedTrusted
		assert.NoError(t, pmgconfig.PreprocessPackageRefs(&rc.Config))
	})

	// Trusted AND blocked: block must win, and analysis must never run.
	rc.Config.BlockedPackages = []pmgconfig.BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "banned by policy"}}
	rc.Config.TrustedPackages = []pmgconfig.TrustedPackage{{Purl: "pkg:npm/left-pad"}}
	require.NoError(t, pmgconfig.PreprocessPackageRefs(&rc.Config))

	guardConfig := DefaultPackageManagerGuardConfig()
	guardConfig.DryRun = true
	guardConfig.ResolveDependencies = false

	rec := &recordingAnalyzer{}
	pg, err := NewPackageManagerGuard(guardConfig, nil, nil,
		[]analyzer.PackageVersionAnalyzer{rec}, PackageManagerGuardInteraction{
			ShowWarning: func(string) {},
		}, noopExecutor)
	require.NoError(t, err)

	parsedCommand := &packagemanager.ParsedCommand{
		Command: packagemanager.Command{Exe: "npm", Args: []string{"install", "left-pad@1.3.0"}},
		InstallTargets: []*packagemanager.PackageInstallTarget{
			{
				PackageVersion: &packagev1.PackageVersion{
					Package: &packagev1.Package{
						Name:      "left-pad",
						Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
					},
					Version: "1.3.0",
				},
			},
		},
	}

	result, err := pg.Run(context.Background(), []string{"npm", "install", "left-pad@1.3.0"}, parsedCommand)
	require.NoError(t, err)

	assert.Equal(t, 0, rec.calls, "blocklisted package must not be analyzed")
	assert.Greater(t, result.BlockedCount, 0)
	require.Len(t, result.BlocklistBlocked, 1)
	assert.Equal(t, models.BlocklistBlock{Name: "left-pad", Version: "1.3.0", Reason: "banned by policy"}, result.BlocklistBlocked[0])
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./guard/ -run TestGuardBlocklistedPackage -v -count=1`
Expected: FAIL to compile — `result.BlocklistBlocked` undefined.

- [ ] **Step 3: Implement guard-side enforcement**

In `guard/guard.go`, add to `GuardResult`:

```go
	// BlocklistBlocked records packages blocked by the blocked_packages policy.
	BlocklistBlocked []models.BlocklistBlock
```

Add the check method (near `concurrentAnalyzePackages`); it runs before trusted-package skipping and before any analysis, so an explicit block beats trust:

```go
// checkBlocklistedPackages scans the resolved set against blocked_packages and
// records hits on the result. It runs before trusted-package skipping and
// before any malware analysis: an explicit block beats trust.
func (g *packageManagerGuard) checkBlocklistedPackages(packages []*packagev1.PackageVersion, result *GuardResult) bool {
	for _, pkg := range packages {
		blocked, ok := config.FindBlockedPackage(pkg)
		if !ok {
			continue
		}

		log.Warnf("Blocking blocklisted package %s/%s@%s",
			pkg.GetPackage().GetEcosystem().String(), pkg.GetPackage().GetName(), pkg.GetVersion())
		audit.LogBlocklistBlocked(pkg, blocked.Reason)

		result.BlockedCount++
		result.BlocklistBlocked = append(result.BlocklistBlocked, models.BlocklistBlock{
			Name:    pkg.GetPackage().GetName(),
			Version: pkg.GetVersion(),
			Reason:  blocked.Reason,
		})
	}

	return len(result.BlocklistBlocked) > 0
}
```

In `Run`, insert after dependency resolution and before the "Checking N packages for malware" debug line (~line 190):

```go
	if g.checkBlocklistedPackages(packagesToAnalyze, result) {
		result.TotalAnalyzed = len(packagesToAnalyze)
		g.clearStatus()
		return result, nil
	}
```

In `handleManifestInstallation`, insert the same block after `packagesToAnalyze` is fully assembled and before the `concurrentAnalyzePackages` call (~line 428):

```go
	if g.checkBlocklistedPackages(packagesToAnalyze, result) {
		result.TotalAnalyzed = len(packagesToAnalyze)
		g.clearStatus()
		return result, nil
	}
```

Add `"github.com/safedep/pmg/internal/models"` to the imports.

- [ ] **Step 4: Run tests**

Run: `go build ./... && go test ./guard/ -count=1`
Expected: PASS (note: some pre-existing guard tests hit the live malysis service; if only those fail without network, they fail the same way on `main` — verify with `git stash && go test ./guard/ -count=1; git stash pop` before assuming this change caused it).

- [ ] **Step 5: Commit**

```bash
git add guard/
git commit -m "feat(guard): block blocklisted packages before trust skip and analysis"
```

---

### Task 5: UI report — blocklist section, custom messages, silent-mode fix

**Files:**
- Modify: `internal/ui/report.go` (ReportData ~line 63, `reportSilent` ~line 140, `reportNormal` ~line 145, `reportVerbose` ~line 226, `printOutcomeLine` ~line 313, `HasIssues` ~line 112)
- Modify: `internal/ui/ui.go` (new print helpers, near `printCooldownPackagesList` ~line 208)
- Create: `internal/ui/report_test.go`
- Modify: `internal/flows/proxy_flow.go` (~line 293)
- Modify: `internal/flows/common_flow.go` (~line 101)

**Interfaces:**
- Consumes: `models.BlocklistBlock` (Task 2), `GetBlocklistBlocks` (Task 3), `GuardResult.BlocklistBlocked` (Task 4), `cfg.Config.Malware.Message` / `cfg.Config.DependencyCooldown.Message` (Task 1).
- Produces: `ReportData.BlocklistBlockedPackages []models.BlocklistBlock`, `ReportData.CooldownMessage string`, `ReportData.MalwareMessage string`.

- [ ] **Step 1: Write the failing tests**

Create `internal/ui/report_test.go`:

```go
package ui

import (
	"io"
	"os"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func withVerbosity(t *testing.T, level VerbosityLevel) {
	t.Helper()
	SetVerbosityLevel(level)
	t.Cleanup(func() { SetVerbosityLevel(VerbosityLevelNormal) })
}

func malwareBlockedData() *ReportData {
	data := NewReportData()
	data.TotalAnalyzed = 1
	data.BlockedCount = 1
	data.Outcome = OutcomeBlocked
	data.BlockedPackages = []*analyzer.PackageVersionAnalysisResult{
		{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{Name: "evil", Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
				Version: "1.0.0",
			},
			Summary: "verified malware",
		},
	}
	return data
}

func TestReportNormalMalwareCustomMessage(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	data := malwareBlockedData()
	data.MalwareMessage = "Contact #security-help"

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Malicious package blocked")
	assert.Contains(t, out, "Contact #security-help")
}

func TestReportNormalNoCustomMessageWhenUnset(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	out := captureStdout(t, func() { Report(malwareBlockedData()) })
	assert.Contains(t, out, "Malicious package blocked")
	assert.NotContains(t, out, "Contact #security-help")
}

func TestReportNormalCooldownCustomMessage(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	data := NewReportData()
	data.TotalAnalyzed = 1
	data.BlockedCount = 1
	data.Outcome = OutcomeBlocked
	data.CooldownBlockedPackages = []models.CooldownBlock{{Name: "fresh", Version: "2.0.0", DaysAgo: 1, DaysLeft: 4, CooldownDays: 5}}
	data.CooldownMessage = "Request an exemption at go/pmg-exceptions"

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Dependency cooldown")
	assert.Contains(t, out, "Request an exemption at go/pmg-exceptions")
}

func TestReportNormalBlocklistSection(t *testing.T) {
	withVerbosity(t, VerbosityLevelNormal)

	data := NewReportData()
	data.TotalAnalyzed = 1
	data.BlockedCount = 1
	data.Outcome = OutcomeBlocked
	data.BlocklistBlockedPackages = []models.BlocklistBlock{{Name: "left-pad", Version: "1.3.0", Reason: "deprecated internally"}}

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Blocked by package policy")
	assert.Contains(t, out, "left-pad@1.3.0")
	assert.Contains(t, out, "deprecated internally")
}

func TestReportSilentRendersBlocks(t *testing.T) {
	withVerbosity(t, VerbosityLevelSilent)

	data := malwareBlockedData()
	data.MalwareMessage = "Contact #security-help"
	data.BlocklistBlockedPackages = []models.BlocklistBlock{{Name: "left-pad", Version: "1.3.0", Reason: "banned"}}

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Malicious package blocked")
	assert.Contains(t, out, "Contact #security-help")
	assert.Contains(t, out, "Blocked by package policy")
}

func TestReportSilentQuietOnSuccess(t *testing.T) {
	withVerbosity(t, VerbosityLevelSilent)

	data := NewReportData()
	data.TotalAnalyzed = 3

	out := captureStdout(t, func() { Report(data) })
	assert.Empty(t, out)
}

func TestReportSilentCooldownOnlyStaysQuiet(t *testing.T) {
	withVerbosity(t, VerbosityLevelSilent)

	data := NewReportData()
	data.TotalAnalyzed = 1
	data.BlockedCount = 1
	data.Outcome = OutcomeBlocked
	data.CooldownBlockedPackages = []models.CooldownBlock{{Name: "fresh", Version: "2.0.0"}}

	out := captureStdout(t, func() { Report(data) })
	assert.Empty(t, out)
}

func TestReportVerboseBlocklistDetails(t *testing.T) {
	withVerbosity(t, VerbosityLevelVerbose)

	data := NewReportData()
	data.TotalAnalyzed = 1
	data.BlockedCount = 1
	data.Outcome = OutcomeBlocked
	data.BlocklistBlockedPackages = []models.BlocklistBlock{{Name: "left-pad", Version: "1.3.0", Reason: "deprecated internally"}}

	out := captureStdout(t, func() { Report(data) })
	assert.Contains(t, out, "Blocked by package policy")
	assert.Contains(t, out, "deprecated internally")
	assert.Contains(t, out, "Installation blocked")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/ui/ -run TestReport -v -count=1`
Expected: FAIL to compile — `data.MalwareMessage`, `data.BlocklistBlockedPackages` undefined.

- [ ] **Step 3: Implement report changes**

In `internal/ui/report.go`, add to `ReportData` (after `CooldownBlockedPackages`):

```go
	// Packages blocked by the blocked_packages policy
	BlocklistBlockedPackages []models.BlocklistBlock

	// Optional org-configured messages appended to block output. Set from
	// dependency_cooldown.message and malware.message config.
	CooldownMessage string
	MalwareMessage  string
```

Update `HasIssues`:

```go
func (r *ReportData) HasIssues() bool {
	return r.BlockedCount > 0 || r.ConfirmedCount > 0 ||
		len(r.CooldownBlockedPackages) > 0 || len(r.BlocklistBlockedPackages) > 0
}
```

Extract the malware and blocklist block sections so `reportNormal` and `reportSilent` share them (DRY). In `report.go`:

```go
func printMalwareBlockSection(data *ReportData) {
	if len(data.BlockedPackages) == 0 {
		return
	}

	fmt.Println()
	fmt.Printf("%s %s\n", Colors.Red("✗"), Colors.Red("Malicious package blocked"))
	printMaliciousPackagesList(data.BlockedPackages)
	printCustomMessage(data.MalwareMessage)
	fmt.Println()
}

func printBlocklistBlockSection(data *ReportData) {
	if len(data.BlocklistBlockedPackages) == 0 {
		return
	}

	fmt.Println()
	fmt.Printf("%s %s\n", Colors.Red("⊘"),
		Colors.Red(fmt.Sprintf("Blocked by package policy — %s", pluralizePackages(len(data.BlocklistBlockedPackages)))))
	printBlocklistPackagesList(data.BlocklistBlockedPackages)
	fmt.Println()
}
```

Replace `reportSilent`:

```go
// reportSilent shows output only when the install was blocked: silent mode
// hides PMG except for errors and block decisions (malware and policy).
// Cooldown-only blocks stay hidden, matching the documented silent contract.
func reportSilent(data *ReportData) {
	if data.Outcome != OutcomeBlocked {
		return
	}

	printMalwareBlockSection(data)
	printBlocklistBlockSection(data)
}
```

In `reportNormal`, replace the inline malware section under `case OutcomeBlocked:` with `printMalwareBlockSection(data)`, add `printBlocklistBlockSection(data)` right after it, and append the cooldown message inside the cooldown section:

```go
	case OutcomeBlocked:
		printMalwareBlockSection(data)
		printBlocklistBlockSection(data)

		if len(data.CooldownBlockedPackages) > 0 {
			fmt.Println()
			n := len(data.CooldownBlockedPackages)
			fmt.Printf("%s %s\n",
				Colors.Yellow("⊘"),
				Colors.Yellow(fmt.Sprintf("Dependency cooldown — %s blocked", pluralizePackages(n))))
			printCooldownPackagesList(data.CooldownBlockedPackages)
			printCustomMessage(data.CooldownMessage)
			fmt.Println()
		}

		onlyCooldown := len(data.BlockedPackages) == 0 && len(data.BlocklistBlockedPackages) == 0 &&
			len(data.CooldownBlockedPackages) > 0
		// ... rest unchanged
```

In `printOutcomeLine`, replace the `OutcomeBlocked` case with a composed reason list:

```go
	case OutcomeBlocked:
		var parts []string
		if len(data.BlockedPackages) > 0 {
			parts = append(parts, "malicious package detected")
		}
		if len(data.BlocklistBlockedPackages) > 0 {
			parts = append(parts, "package blocklist policy")
		}
		if len(data.CooldownBlockedPackages) > 0 {
			parts = append(parts, "cooldown policy")
		}
		if len(parts) == 0 {
			parts = append(parts, "malicious package detected")
		}

		reason := strings.Join(parts, " + ")
		onlyCooldown := len(data.BlockedPackages) == 0 && len(data.BlocklistBlockedPackages) == 0
		if onlyCooldown {
			fmt.Printf("  %s %s\n", Colors.Yellow("⊘"), Colors.Yellow(fmt.Sprintf("Installation blocked — %s", reason)))
		} else {
			fmt.Printf("  %s %s\n", Colors.Red("✗"), Colors.Red(fmt.Sprintf("Installation blocked — %s", reason)))
		}
```

(add `"strings"` to report.go imports; the pre-existing "dependency cooldown policy" wording becomes "cooldown policy" so combinations stay readable.)

In `reportVerbose`, append `printCustomMessage(data.MalwareMessage)` after the `Blocked packages:` detail loop, `printCustomMessage(data.CooldownMessage)` after the cooldown detail loop, and add a blocklist detail section after the cooldown one:

```go
	if len(data.BlocklistBlockedPackages) > 0 {
		fmt.Println()
		fmt.Println(Colors.Red("  Blocked by package policy:"))
		for _, pkg := range data.BlocklistBlockedPackages {
			fmt.Printf("    %s %s\n", Colors.Red("⊘"), Colors.Red(fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)))
			if pkg.Reason != "" {
				fmt.Printf("      %s\n", Colors.Dim(termWidthFormatText(pkg.Reason, 76)))
			}
		}
	}
```

In `internal/ui/ui.go`, add near `printCooldownPackagesList`:

```go
func printBlocklistPackagesList(packages []models.BlocklistBlock) {
	for _, pkg := range packages {
		fmt.Println()
		fmt.Printf("  %s %s\n", Colors.Red("⊘"), Colors.Red(fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)))
		if pkg.Reason != "" {
			fmt.Printf("    %s\n", Colors.Dim(termWidthFormatText(pkg.Reason, 76)))
		}
	}
}

// printCustomMessage renders an org-configured message appended to a block
// section. No-op when the message is empty.
func printCustomMessage(message string) {
	if message == "" {
		return
	}
	fmt.Println()
	fmt.Printf("  %s\n", termWidthFormatText(message, 76))
}
```

Also sync the now-stale silent-mode doc strings to mention policy blocks:
- `internal/ui/ui.go:21-22` — change the `VerbosityLevelSilent` comment to "PMG is hidden from the user except for errors and block decisions (malicious packages and the blocked_packages policy)".
- `config/config.template.yml:14` — change the `silent` description line to "silent: PMG is hidden from the user except for errors, malicious package detection, and policy blocks".

- [ ] **Step 4: Plumb from the flows**

In `internal/flows/proxy_flow.go` (after `reportData.CooldownBlockedPackages = ...`, ~line 293):

```go
	reportData.BlocklistBlockedPackages = statsCollector.GetBlocklistBlocks()
	reportData.CooldownMessage = cfg.Config.DependencyCooldown.Message
	reportData.MalwareMessage = cfg.Config.Malware.Message
```

In `internal/flows/common_flow.go` (inside `if guardResult != nil`, after `ConfirmedPackages`, ~line 102):

```go
		reportData.BlocklistBlockedPackages = guardResult.BlocklistBlocked
```

and after that block (config-derived, not guard-derived):

```go
	reportData.CooldownMessage = cfg.Config.DependencyCooldown.Message
	reportData.MalwareMessage = cfg.Config.Malware.Message
```

- [ ] **Step 5: Run tests**

Run: `go build ./... && go test ./internal/ui/ ./internal/flows/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/ui/ internal/flows/
git commit -m "feat(ui): render blocklist blocks and custom messages, fix silent-mode block output"
```

---

### Task 6: Custom messages in proxy 403 bodies

**Files:**
- Modify: `proxy/interceptors/base_registry.go` (`handleAnalysisResult` ActionBlock ~line 197 and user-declined ~line 236)
- Modify: `proxy/interceptors/go_cooldown.go` (~line 129)
- Modify: `proxy/interceptors/base_registry_test.go`

**Interfaces:**
- Consumes: `config.Get().Config.Malware.Message`, `config.Get().Config.DependencyCooldown.Message` (Task 1).
- Produces: `appendCustomMessage(message, custom string) string` (package-internal helper).

- [ ] **Step 1: Write the failing test**

Add to `proxy/interceptors/base_registry_test.go`:

```go
func TestAppendCustomMessage(t *testing.T) {
	assert.Equal(t, "base", appendCustomMessage("base", ""))
	assert.Equal(t, "base\n\ncustom", appendCustomMessage("base", "custom"))
}

func TestHandleAnalysisResultBlockCarriesMalwareMessage(t *testing.T) {
	origMsg := pmgconfig.Get().Config.Malware.Message
	pmgconfig.Get().Config.Malware.Message = "Contact #security-help"
	t.Cleanup(func() { pmgconfig.Get().Config.Malware.Message = origMsg })

	b := &baseRegistryInterceptor{}
	ctx := makeTestRequestContext("https://registry.npmjs.org/evil/-/evil-1.0.0.tgz")

	result := &analyzer.PackageVersionAnalysisResult{
		PackageVersion: &packagev1.PackageVersion{
			Package: &packagev1.Package{Name: "evil", Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM},
			Version: "1.0.0",
		},
		Action:  analyzer.ActionBlock,
		Summary: "verified malware",
	}

	resp, err := b.handleAnalysisResult(ctx, packagev1.Ecosystem_ECOSYSTEM_NPM, "evil", "1.0.0", result)
	require.NoError(t, err)
	assert.Equal(t, proxy.ActionBlock, resp.Action)
	assert.Contains(t, resp.BlockMessage, "Contact #security-help")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./proxy/interceptors/ -run 'TestAppendCustomMessage|TestHandleAnalysisResultBlockCarriesMalwareMessage' -v -count=1`
Expected: FAIL to compile — `undefined: appendCustomMessage`.

- [ ] **Step 3: Implement**

In `proxy/interceptors/base_registry.go`, add:

```go
// appendCustomMessage appends the org-configured message, when set, to a
// block message body.
func appendCustomMessage(message, custom string) string {
	if custom == "" {
		return message
	}
	return message + "\n\n" + custom
}
```

In `handleAnalysisResult`, wrap both malware block bodies. The `ActionBlock` case (~line 197):

```go
		message := appendCustomMessage(fmt.Sprintf("Malicious package blocked: %s/%s@%s\n\nReason: %s\n\nReference: %s",
			ecosystem.String(),
			packageName, packageVersion,
			result.Summary,
			result.ReferenceURL), config.Get().Config.Malware.Message)
```

and the user-declined case (~line 236):

```go
			message := appendCustomMessage(fmt.Sprintf("Installation blocked by user: %s/%s@%s\n\nReason: %s\n\nReference: %s",
				ecosystem.String(),
				packageName, packageVersion,
				result.Summary,
				result.ReferenceURL), config.Get().Config.Malware.Message)
```

In `proxy/interceptors/go_cooldown.go` (~line 129), the Go cooldown 403 is the one cooldown path with a response body (npm/pypi only strip metadata):

```go
	message := appendCustomMessage(
		fmt.Sprintf("Package blocked by dependency cooldown: GO/%s@%s\n\nPublished %d day(s) ago; cooldown window is %d day(s) (%d remaining).",
			module, version, daysAgo, cooldownDays, daysLeft),
		pmgconfig.Get().Config.DependencyCooldown.Message)
```

(`go_cooldown.go` already imports `pmgconfig "github.com/safedep/pmg/config"`; `base_registry.go` imports it as `config`.)

- [ ] **Step 4: Run tests**

Run: `go build ./... && go test ./proxy/interceptors/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add proxy/interceptors/
git commit -m "feat(proxy): append custom messages to malware and go-cooldown block bodies"
```

---

### Task 7: Proxy E2E cases and docs

**Files:**
- Modify: `test/proxye2e/runner.go` (`applyConfig` baseline, ~line 58)
- Modify: `test/proxye2e/proxye2e_test.go` (new test function)
- Create: `docs/blocked-packages.md`
- Modify: `docs/config.md` (add the three new keys, following the file's existing format)

**Interfaces:**
- Consumes: everything from Tasks 1–6. No new interfaces produced.

- [ ] **Step 1: Harden the E2E config baseline**

In `test/proxye2e/runner.go` `applyConfig`, add to the reset block (after `rc.Config.DependencyCooldown = ...`):

```go
	rc.Config.BlockedPackages = nil
	rc.Config.Malware = config.MalwareConfig{}
```

(The `PreprocessTrustedPackages` → `PreprocessPackageRefs` rename already happened in Task 1.)

- [ ] **Step 2: Write the E2E cases**

Add to `test/proxye2e/proxye2e_test.go`:

```go
func blockedBody(res ExecResult) string {
	for _, r := range res.Requests {
		if r.Blocked {
			return r.Body
		}
	}
	return ""
}

func TestProxyFlow_Blocklist(t *testing.T) {
	addLeftPad := func(h *Harness) {
		h.Registry.AddNpm(NpmPackage{Name: "left-pad", DistTagLatest: "2.0.0", Versions: []NpmVersion{
			{Version: "1.0.0", PublishedAt: old()},
			{Version: "2.0.0", PublishedAt: old()},
		}})
	}

	RunCases(t, []TestCase{
		{
			Name: "blocklisted package blocked without analysis",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.BlockedPackages = []config.BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "deprecated internally"}}
			},
			Setup: addLeftPad,
			Exec:  func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Empty(t, h.Analyzer.Calls(), "blocklisted package must not reach the analyzer")
				assert.False(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
				assert.Contains(t, blockedBody(res), "deprecated internally")

				blocks := h.BlocklistBlocks()
				assert.NotEmpty(t, blocks)
				assert.Equal(t, "left-pad", blocks[0].Name)
			},
		},
		{
			Name: "version-pinned blocklist entry blocks only that version",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.BlockedPackages = []config.BlockedPackage{{Purl: "pkg:npm/left-pad@1.0.0", Reason: "bad build"}}
			},
			Setup: addLeftPad,
			Exec: func(h *Harness) ExecResult {
				res := h.Npm().Install("left-pad", "1.0.0")
				for _, r := range h.Npm().Install("left-pad", "2.0.0").Requests {
					res.Requests = append(res.Requests, r)
				}
				return res
			},
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "2.0.0"), "unpinned version must install")
			},
		},
		{
			Name: "blocklist wins over trusted_packages",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.TrustedPackages = []config.TrustedPackage{{Purl: "pkg:npm/left-pad"}}
				rc.Config.BlockedPackages = []config.BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "banned"}}
			},
			Setup: addLeftPad,
			Exec:  func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.False(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
			},
		},
		{
			Name: "insecure installation bypasses blocklist",
			Config: func(rc *config.RuntimeConfig) {
				rc.InsecureInstallation = true
				rc.Config.BlockedPackages = []config.BlockedPackage{{Purl: "pkg:npm/left-pad", Reason: "banned"}}
			},
			Setup: addLeftPad,
			Exec:  func(h *Harness) ExecResult { return h.Npm().Install("left-pad", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.False(t, res.Blocked())
				assert.True(t, h.Registry.DownloadedTarball("left-pad", "1.0.0"))
			},
		},
		{
			Name: "malware block body carries custom malware message",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.Malware = config.MalwareConfig{Message: "Report false positives in #security-help"}
			},
			Setup: func(h *Harness) {
				h.Registry.AddNpm(NpmPackage{Name: "evil", DistTagLatest: "1.0.0",
					Versions: []NpmVersion{{Version: "1.0.0", PublishedAt: old()}}})
				h.Analyzer.SetNpm("evil", "1.0.0", VerifiedMalware())
			},
			Exec: func(h *Harness) ExecResult { return h.Npm().Install("evil", "1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Contains(t, blockedBody(res), "Report false positives in #security-help")
			},
		},
		{
			Name: "go cooldown block body carries custom cooldown message",
			Config: func(rc *config.RuntimeConfig) {
				rc.Config.DependencyCooldown = config.DependencyCooldownConfig{
					Enabled: true,
					Days:    7,
					Message: "Request an exemption at go/pmg-exceptions",
				}
			},
			Setup: func(h *Harness) {
				h.Registry.AddGoModule(GoModule{Path: "example.com/fresh",
					Versions: []GoVersion{{Version: "v1.0.0", PublishedAt: recent()}}})
			},
			Exec: func(h *Harness) ExecResult { return h.Go().Install("example.com/fresh", "v1.0.0") },
			Assert: func(t *testing.T, h *Harness, res ExecResult) {
				assert.True(t, res.Blocked())
				assert.Contains(t, blockedBody(res), "Request an exemption at go/pmg-exceptions")
			},
		},
	})
}
```

Note for the implementer: the Go cooldown case blocks at `.zip` download (`go_cooldown.go` handles download requests; `.info`/`.mod` metadata pass through). If the case fails, check which request carried the 403 with `res.Requests` before changing product code — compare against the existing Go cooldown case at `proxye2e_test.go:365+`.

- [ ] **Step 3: Run the E2E suite**

Run: `go test ./test/proxye2e/ -v -count=1`
Expected: PASS, including all pre-existing cases.

- [ ] **Step 4: Write docs**

Create `docs/blocked-packages.md` (model tone/structure on `docs/trusted-packages.md`): what `blocked_packages` does, matching semantics (version-less = all versions), block-beats-trust precedence, insecure-mode exception, the audit event name `package_blocklist_blocked`, and a config example matching the template. Update `docs/config.md` with `dependency_cooldown.message`, `malware.message`, and `blocked_packages` entries following that file's existing format.

- [ ] **Step 5: Full verification**

Run: `go build ./... && go test ./... -count=1`
Expected: PASS (pre-existing network-dependent guard tests excepted — verify any failure also occurs on `main` before investigating).

- [ ] **Step 6: Commit**

```bash
git add test/proxye2e/ docs/
git commit -m "test(proxye2e): cover blocklist enforcement and custom block messages"
```
