# Config Merging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge missing config template keys into existing user configs during `pmg setup install`, preserving all user values, comments, and formatting.

**Architecture:** New `config/merge` package with a pure `MergeYAML(existing, template []byte) ([]byte, error)` function using `goccy/go-yaml` AST manipulation. `WriteTemplateConfig()` in `config/config.go` calls this when a config file already exists.

**Tech Stack:** Go, `github.com/goccy/go-yaml` (AST parser), `github.com/stretchr/testify` (tests)

---

## File Structure

| File | Role |
|------|------|
| Create: `config/merge/merge.go` | Pure YAML AST merge function |
| Create: `config/merge/merge_test.go` | Comprehensive table-driven tests |
| Modify: `config/config.go:349-375` | Update `WriteTemplateConfig()` to call merge |
| Modify: `go.mod` | Add `goccy/go-yaml` dependency |

---

### Task 1: Add `goccy/go-yaml` Dependency

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Add the dependency**

Run:
```bash
go get github.com/goccy/go-yaml@latest
```

- [ ] **Step 2: Tidy modules**

Run:
```bash
go mod tidy
```

- [ ] **Step 3: Verify it resolved**

Run:
```bash
grep goccy go.mod
```
Expected: A line like `github.com/goccy/go-yaml v0.x.x`

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add goccy/go-yaml dependency for config merging"
```

---

### Task 2: Write Failing Tests for Core Merge Logic

**Files:**
- Create: `config/merge/merge.go` (minimal stub)
- Create: `config/merge/merge_test.go`

- [ ] **Step 1: Create minimal stub for `merge.go`**

Create `config/merge/merge.go`:

```go
package merge

// MergeYAML merges missing keys from template into existing YAML config.
// It preserves all existing user values, comments, and formatting.
// Only keys present in template but absent in existing are added.
func MergeYAML(existing []byte, template []byte) ([]byte, error) {
	return nil, nil
}
```

- [ ] **Step 2: Write table-driven tests**

Create `config/merge/merge_test.go` with the following test cases. Each case is a subtest in a single `TestMergeYAML` function using `t.Run`:

```go
package merge

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeYAML(t *testing.T) {
	tests := []struct {
		name     string
		existing string
		template string
		// wantKeys are key: value pairs that MUST appear in the output.
		// We parse the output as YAML and check these.
		wantKeys map[string]any
		// wantRaw are substrings that MUST appear in the raw output string.
		// Used to verify comments and formatting are preserved.
		wantRaw []string
		// wantAbsentRaw are substrings that must NOT appear in the raw output.
		wantAbsentRaw []string
		wantErr       bool
	}{
		{
			name:     "new top-level key is appended",
			existing: "port: 8080\n",
			template: "port: 3000\nhost: localhost\n",
			wantKeys: map[string]any{"port": uint64(8080), "host": "localhost"},
		},
		{
			name:     "existing value is never overwritten",
			existing: "port: 8080\n",
			template: "port: 3000\n",
			wantKeys: map[string]any{"port": uint64(8080)},
		},
		{
			name: "nested key added under existing parent",
			existing: "server:\n  port: 8080\n",
			template: "server:\n  port: 3000\n  host: localhost\n",
			wantKeys: map[string]any{
				"server": map[string]any{"port": uint64(8080), "host": "localhost"},
			},
		},
		{
			name: "deeply nested key added",
			existing: "a:\n  b:\n    c: 1\n",
			template: "a:\n  b:\n    c: 2\n    d: 3\n",
			wantKeys: map[string]any{
				"a": map[string]any{
					"b": map[string]any{"c": uint64(1), "d": uint64(3)},
				},
			},
		},
		{
			name:     "user-only keys are preserved",
			existing: "port: 8080\ncustom: myval\n",
			template: "port: 3000\n",
			wantKeys: map[string]any{"port": uint64(8080), "custom": "myval"},
		},
		{
			name:     "user comments are preserved",
			existing: "# My custom comment\nport: 8080\n",
			template: "port: 3000\nhost: localhost\n",
			wantRaw:  []string{"# My custom comment"},
			wantKeys: map[string]any{"port": uint64(8080)},
		},
		{
			name:     "template comments come with new keys",
			existing: "port: 8080\n",
			template: "port: 3000\n# The hostname\nhost: localhost\n",
			wantRaw:  []string{"# The hostname"},
			wantKeys: map[string]any{"host": "localhost"},
		},
		{
			name:     "empty existing config gets all template keys",
			existing: "",
			template: "port: 3000\nhost: localhost\n",
			wantKeys: map[string]any{"port": uint64(3000), "host": "localhost"},
		},
		{
			name:     "empty template is no-op",
			existing: "port: 8080\n",
			template: "",
			wantKeys: map[string]any{"port": uint64(8080)},
		},
		{
			name: "type mismatch — user has scalar, template has mapping — user wins",
			existing: "server: simple\n",
			template: "server:\n  port: 8080\n",
			wantKeys: map[string]any{"server": "simple"},
		},
		{
			name: "type mismatch — user has mapping, template has scalar — user wins",
			existing: "server:\n  port: 8080\n",
			template: "server: simple\n",
			wantKeys: map[string]any{
				"server": map[string]any{"port": uint64(8080)},
			},
		},
		{
			name:     "different key order — no duplicates",
			existing: "b: 2\na: 1\n",
			template: "a: 10\nb: 20\nc: 30\n",
			wantKeys: map[string]any{"a": uint64(1), "b": uint64(2), "c": uint64(30)},
		},
		{
			name:    "malformed existing YAML returns error",
			existing: ":\n  invalid: [yaml\n",
			template: "port: 3000\n",
			wantErr:  true,
		},
		{
			name:    "malformed template YAML returns error",
			existing: "port: 8080\n",
			template: ":\n  invalid: [yaml\n",
			wantErr:  true,
		},
		{
			name:     "inline comments on existing keys preserved",
			existing: "port: 8080 # my port\n",
			template: "port: 3000\nhost: localhost\n",
			wantRaw:  []string{"# my port"},
			wantKeys: map[string]any{"port": uint64(8080), "host": "localhost"},
		},
		{
			name: "multiple new top-level keys appended",
			existing: "port: 8080\n",
			template: "port: 3000\nhost: localhost\ntimeout: 30\nretries: 3\n",
			wantKeys: map[string]any{
				"port":    uint64(8080),
				"host":    "localhost",
				"timeout": uint64(30),
				"retries": uint64(3),
			},
		},
		{
			name: "new nested section added entirely",
			existing: "port: 8080\n",
			template: "port: 3000\nserver:\n  host: localhost\n  tls: true\n",
			wantKeys: map[string]any{
				"port": uint64(8080),
				"server": map[string]any{"host": "localhost", "tls": true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := MergeYAML([]byte(tt.existing), []byte(tt.template))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Parse result to check keys
			if len(tt.wantKeys) > 0 {
				parsed := parseYAML(t, result)
				for key, wantVal := range tt.wantKeys {
					assertDeepValue(t, parsed, key, wantVal)
				}
			}

			// Check raw string contains expected substrings
			raw := string(result)
			for _, s := range tt.wantRaw {
				assert.Contains(t, raw, s, "expected raw output to contain %q", s)
			}

			for _, s := range tt.wantAbsentRaw {
				assert.NotContains(t, raw, s, "expected raw output NOT to contain %q", s)
			}
		})
	}
}

// parseYAML is a test helper that unmarshals YAML bytes into a map.
func parseYAML(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	err := yamlUnmarshal(data, &m)
	require.NoError(t, err, "failed to parse merged YAML output")
	return m
}

// assertDeepValue checks that a key in the parsed map matches the expected value.
func assertDeepValue(t *testing.T, parsed map[string]any, key string, expected any) {
	t.Helper()
	actual, ok := parsed[key]
	assert.True(t, ok, "expected key %q to exist in output", key)
	if ok {
		assert.Equal(t, expected, actual, "value mismatch for key %q", key)
	}
}
```

Note: `yamlUnmarshal` is a thin wrapper we'll add in the merge package to use `goccy/go-yaml` for unmarshalling in tests. Add this to `merge.go` stub:

```go
import "github.com/goccy/go-yaml"

func yamlUnmarshal(data []byte, v any) error {
	return yaml.Unmarshal(data, v)
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run:
```bash
cd /Users/sahil/Work/Safedep/pmg && go test ./config/merge/ -v -count=1
```
Expected: Most tests FAIL (stub returns `nil, nil`)

- [ ] **Step 4: Commit**

```bash
git add config/merge/
git commit -m "test: add failing tests for YAML config merge logic"
```

---

### Task 3: Implement Core Merge Logic

**Files:**
- Modify: `config/merge/merge.go`

- [ ] **Step 1: Implement `MergeYAML`**

Replace the stub in `config/merge/merge.go` with the full implementation:

```go
package merge

import (
	"fmt"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// MergeYAML merges missing keys from template into existing YAML config.
// It preserves all existing user values, comments, and formatting.
// Only keys present in template but absent in existing are added.
// If existing is empty, the full template is returned.
func MergeYAML(existing []byte, template []byte) ([]byte, error) {
	if len(trimmedBytes(existing)) == 0 {
		return template, nil
	}

	if len(trimmedBytes(template)) == 0 {
		return existing, nil
	}

	templateFile, err := parser.ParseBytes(template, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	existingFile, err := parser.ParseBytes(existing, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse existing config: %w", err)
	}

	templateRoot, err := mappingRoot(templateFile)
	if err != nil {
		return nil, fmt.Errorf("template: %w", err)
	}

	existingRoot, err := mappingRoot(existingFile)
	if err != nil {
		return nil, fmt.Errorf("existing config: %w", err)
	}

	mergeMappings(existingRoot, templateRoot)
	return []byte(existingFile.String()), nil
}

// mappingRoot extracts the root MappingNode from a parsed YAML file.
func mappingRoot(file *ast.File) (*ast.MappingNode, error) {
	if len(file.Docs) == 0 || file.Docs[0] == nil || file.Docs[0].Body == nil {
		return nil, fmt.Errorf("YAML document is empty")
	}

	root, ok := file.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return nil, fmt.Errorf("root YAML node must be a mapping")
	}

	return root, nil
}

// mergeMappings recursively merges missing keys from src into dst.
// Existing keys in dst are never modified. Only keys present in src
// but absent in dst are appended.
func mergeMappings(dst, src *ast.MappingNode) {
	existing := make(map[string]*ast.MappingValueNode, len(dst.Values))
	for _, v := range dst.Values {
		existing[nodeKey(v)] = v
	}

	for _, srcVal := range src.Values {
		key := nodeKey(srcVal)
		dstVal, found := existing[key]

		if !found {
			appendWithSpacing(dst, srcVal)
			continue
		}

		// Both exist — recurse only if both are mappings
		dstMapping, dstOk := dstVal.Value.(*ast.MappingNode)
		srcMapping, srcOk := srcVal.Value.(*ast.MappingNode)
		if dstOk && srcOk {
			mergeMappings(dstMapping, srcMapping)
		}
	}
}

// nodeKey returns the string key of a mapping value node.
func nodeKey(v *ast.MappingValueNode) string {
	if tok := v.Key.GetToken(); tok != nil {
		return tok.Value
	}

	return v.Key.String()
}

// appendWithSpacing appends a mapping value from the template to the dst
// mapping, inserting a blank line before it for readability.
func appendWithSpacing(dst *ast.MappingNode, srcVal *ast.MappingValueNode) {
	if len(dst.Values) > 0 {
		lastVal := dst.Values[len(dst.Values)-1]
		lastTok := lastVal.Key.GetToken()
		for lastTok.Next != nil {
			lastTok = lastTok.Next
		}

		newTok := srcVal.Key.GetToken()
		newTok.Prev = lastTok
		lastTok.Next = newTok

		targetLine := lastTok.Position.Line + 2
		shift := targetLine - newTok.Position.Line
		if shift > 0 {
			for tok := newTok; tok != nil; tok = tok.Next {
				tok.Position.Line += shift
			}
		}
	}

	dst.Values = append(dst.Values, srcVal)
}

// trimmedBytes returns bytes with leading/trailing whitespace removed.
func trimmedBytes(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\n' || b[end-1] == '\r') {
		end--
	}

	return b[start:end]
}

// yamlUnmarshal wraps goccy/go-yaml Unmarshal for use in tests.
func yamlUnmarshal(data []byte, v any) error {
	return yaml.Unmarshal(data, v)
}
```

- [ ] **Step 2: Run tests**

Run:
```bash
cd /Users/sahil/Work/Safedep/pmg && go test ./config/merge/ -v -count=1
```
Expected: All tests PASS

- [ ] **Step 3: Fix any failing tests**

If tests fail, debug and fix the implementation. Re-run until all pass.

- [ ] **Step 4: Commit**

```bash
git add config/merge/merge.go
git commit -m "feat: implement YAML AST merge for config keys"
```

---

### Task 4: Integration Test with Real PMG Config Template

**Files:**
- Modify: `config/merge/merge_test.go`

- [ ] **Step 1: Write integration test using the actual PMG template**

Add this test to `config/merge/merge_test.go`:

```go
func TestMergeWithPMGTemplate(t *testing.T) {
	// Simulate a user config that has a subset of the real template keys.
	// After merge, new keys from the template should appear while
	// user customizations are preserved.
	userConfig := `# My PMG config
transitive: false
transitive_depth: 10
verbosity: verbose
proxy_mode: false
# My custom trusted packages
trusted_packages:
  - purl: pkg:npm/my-internal-lib
    reason: "Internal library"
sandbox:
  enabled: true
  enforce_always: true
  policies:
    npm:
      enabled: false
      profile: npm-restrictive
`

	template := `# PMG configuration template. Customize this file as needed.
# https://github.com/safedep/pmg

transitive: true
transitive_depth: 5
include_dev_dependencies: false
verbosity: normal
paranoid: false
skip_event_logging: false
event_log_retention_days: 7
proxy_mode: true
trusted_packages:
  - purl: pkg:npm/@safedep/pmg
    reason: "PMG is a trusted package for PMG"
sandbox:
  enabled: false
  enforce_always: false
  policy_templates:
    npm-restrictive-override:
      path: ./profiles/npm-restrictive.yml
  policies:
    npm:
      enabled: true
      profile: npm-restrictive
    pnpm:
      enabled: true
      profile: pnpm-restrictive
`

	result, err := MergeYAML([]byte(userConfig), []byte(template))
	require.NoError(t, err)

	raw := string(result)

	// User values preserved
	assert.Contains(t, raw, "# My PMG config")
	assert.Contains(t, raw, "# My custom trusted packages")

	// Parse to check values
	parsed := parseYAML(t, result)

	// User's customized values are kept
	assert.Equal(t, false, parsed["transitive"])
	assert.Equal(t, uint64(10), parsed["transitive_depth"])
	assert.Equal(t, "verbose", parsed["verbosity"])
	assert.Equal(t, false, parsed["proxy_mode"])

	// New keys from template are added
	assert.Equal(t, false, parsed["include_dev_dependencies"])
	assert.Equal(t, false, parsed["paranoid"])
	assert.Equal(t, false, parsed["skip_event_logging"])
	assert.Equal(t, uint64(7), parsed["event_log_retention_days"])

	// Sandbox: user's enabled=true preserved, new sub-keys added
	sandbox, ok := parsed["sandbox"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, sandbox["enabled"])
	assert.Equal(t, true, sandbox["enforce_always"])

	// policy_templates should be added (missing from user config)
	assert.NotNil(t, sandbox["policy_templates"], "policy_templates should be merged from template")

	// User's npm policy override preserved
	policies, ok := sandbox["policies"].(map[string]any)
	require.True(t, ok)
	npm, ok := policies["npm"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, false, npm["enabled"], "user disabled npm sandbox, should be preserved")

	// pnpm policy added from template
	assert.NotNil(t, policies["pnpm"], "pnpm policy should be merged from template")
}
```

- [ ] **Step 2: Run the test**

Run:
```bash
cd /Users/sahil/Work/Safedep/pmg && go test ./config/merge/ -run TestMergeWithPMGTemplate -v -count=1
```
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add config/merge/merge_test.go
git commit -m "test: add integration test with real PMG config template shape"
```

---

### Task 5: Integrate Merge into `WriteTemplateConfig()`

**Files:**
- Modify: `config/config.go:349-375`

- [ ] **Step 1: Write failing test for `WriteTemplateConfig` merge behavior**

Add to `config/config_test.go`:

```go
func TestWriteTemplateConfigMergesExistingConfig(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)

	configPath := filepath.Join(tmpDir, "config.yml")

	// Write a partial user config
	userConfig := []byte("transitive: false\ntransitive_depth: 10\n")
	err := os.WriteFile(configPath, userConfig, 0o644)
	assert.NoError(t, err)

	// Re-init so paths point to tmpDir
	initConfig()

	// Run WriteTemplateConfig — should merge, not skip
	err = WriteTemplateConfig()
	assert.NoError(t, err)

	// Read back
	result, err := os.ReadFile(configPath)
	assert.NoError(t, err)

	raw := string(result)

	// User values preserved
	assert.Contains(t, raw, "transitive: false")
	assert.Contains(t, raw, "transitive_depth: 10")

	// New keys from template added
	assert.Contains(t, raw, "proxy_mode:")
	assert.Contains(t, raw, "sandbox:")
	assert.Contains(t, raw, "verbosity:")
}

func TestWriteTemplateConfigCreatesNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PMG_CONFIG_DIR", tmpDir)

	initConfig()

	err := WriteTemplateConfig()
	assert.NoError(t, err)

	configPath := filepath.Join(tmpDir, "config.yml")
	result, err := os.ReadFile(configPath)
	assert.NoError(t, err)

	// Should be the full template
	assert.Equal(t, templateConfig, string(result))
}
```

- [ ] **Step 2: Run the test to see it fail**

Run:
```bash
cd /Users/sahil/Work/Safedep/pmg && go test ./config/ -run TestWriteTemplateConfig -v -count=1
```
Expected: `TestWriteTemplateConfigMergesExistingConfig` FAILS (current code skips if file exists)

- [ ] **Step 3: Modify `WriteTemplateConfig()` in `config/config.go`**

Replace the `WriteTemplateConfig` function (lines 349-375):

```go
// WriteTemplateConfig writes the template configuration file to disk.
// If the config file does not exist, the full template is written.
// If it already exists, missing keys from the template are merged
// into the existing config while preserving all user values and comments.
func WriteTemplateConfig() error {
	configDir, err := configDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configFilePath, err := configFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

	existingConfig, err := os.ReadFile(configFilePath)
	if os.IsNotExist(err) {
		return os.WriteFile(configFilePath, []byte(templateConfig), 0o644)
	}
	if err != nil {
		return fmt.Errorf("failed to read existing config: %w", err)
	}

	merged, err := merge.MergeYAML(existingConfig, []byte(templateConfig))
	if err != nil {
		return fmt.Errorf("failed to merge config: %w", err)
	}

	if err := os.WriteFile(configFilePath, merged, 0o644); err != nil {
		return fmt.Errorf("failed to write merged config: %w", err)
	}

	return nil
}
```

Add the import at the top of `config/config.go`:

```go
import (
	// ... existing imports ...
	"github.com/safedep/pmg/config/merge"
)
```

- [ ] **Step 4: Run tests**

Run:
```bash
cd /Users/sahil/Work/Safedep/pmg && go test ./config/ -v -count=1
```
Expected: All tests PASS (both new and existing)

- [ ] **Step 5: Commit**

```bash
git add config/config.go config/config_test.go
git commit -m "feat: merge template keys into existing config during setup install

Closes #114"
```

---

### Task 6: Run Full Test Suite and Verify

**Files:**
- No changes — verification only

- [ ] **Step 1: Run all tests**

Run:
```bash
cd /Users/sahil/Work/Safedep/pmg && go test ./... -count=1
```
Expected: All tests PASS, no regressions

- [ ] **Step 2: Run linter if configured**

Run:
```bash
cd /Users/sahil/Work/Safedep/pmg && golangci-lint run ./... 2>/dev/null || echo "no linter configured"
```
Expected: No new lint errors

- [ ] **Step 3: Manual smoke test**

Run:
```bash
# Create a temp config dir with a partial config
export PMG_CONFIG_DIR=$(mktemp -d)
echo "transitive: false" > "$PMG_CONFIG_DIR/config.yml"

# Run setup install
go run . setup install

# Check the merged config
cat "$PMG_CONFIG_DIR/config.yml"

# Clean up
unset PMG_CONFIG_DIR
```
Expected: The config file has `transitive: false` (user value) plus all other template keys
