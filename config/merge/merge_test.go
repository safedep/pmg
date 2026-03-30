package merge

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// yamlUnmarshal wraps goccy/go-yaml Unmarshal for use in tests.
func yamlUnmarshal(data []byte, v any) error {
	return yaml.Unmarshal(data, v)
}

// parseYAML is a test helper that unmarshals YAML bytes into a map.
func parseYAML(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	err := yamlUnmarshal(data, &m)
	require.NoError(t, err, "failed to parse YAML result")
	return m
}

// assertDeepValue navigates a nested map by keys and asserts the leaf value.
func assertDeepValue(t *testing.T, m map[string]any, keys []string, expected any) {
	t.Helper()
	current := any(m)
	for i, key := range keys {
		cm, ok := current.(map[string]any)
		require.True(t, ok, "expected map at key path %v (index %d), got %T", keys[:i], i, current)
		current, ok = cm[key]
		require.True(t, ok, "key %q not found at path %v", key, keys[:i+1])
	}
	assert.Equal(t, expected, current)
}

func TestMergeYAML(t *testing.T) {
	tests := []struct {
		name     string
		existing string
		template string
		// check is called with the merged output for custom assertions.
		check func(t *testing.T, merged []byte)
		// wantErr indicates the merge should fail.
		wantErr bool
	}{
		{
			name:     "new top-level key appended",
			existing: "name: alice\n",
			template: "name: default\nage: 30\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "alice", m["name"], "existing value must be kept")
				assert.Equal(t, uint64(30), m["age"], "new key must be added")
			},
		},
		{
			name:     "existing value never overwritten",
			existing: "port: 8080\n",
			template: "port: 3000\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, uint64(8080), m["port"])
			},
		},
		{
			name: "nested key added under existing parent",
			existing: `server:
  host: localhost
`,
			template: `server:
  host: 0.0.0.0
  port: 9090
`,
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assertDeepValue(t, m, []string{"server", "host"}, "localhost")
				assertDeepValue(t, m, []string{"server", "port"}, uint64(9090))
			},
		},
		{
			name: "deeply nested new keys 3+ levels",
			existing: `a:
  b:
    c: 1
`,
			template: `a:
  b:
    c: 99
    d: 2
  e:
    f: 3
`,
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assertDeepValue(t, m, []string{"a", "b", "c"}, uint64(1))
				assertDeepValue(t, m, []string{"a", "b", "d"}, uint64(2))
				assertDeepValue(t, m, []string{"a", "e", "f"}, uint64(3))
			},
		},
		{
			name: "user-only keys preserved",
			existing: `custom: myvalue
name: alice
`,
			template: `name: default
`,
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "myvalue", m["custom"])
				assert.Equal(t, "alice", m["name"])
			},
		},
		{
			name: "user comments preserved",
			existing: `# User's important comment
name: alice
`,
			template: `name: default
age: 30
`,
			check: func(t *testing.T, merged []byte) {
				s := string(merged)
				assert.Contains(t, s, "# User's important comment")
				m := parseYAML(t, merged)
				assert.Equal(t, "alice", m["name"])
				assert.Equal(t, uint64(30), m["age"])
			},
		},
		{
			name:     "template comments come with new keys",
			existing: "name: alice\n",
			template: `name: default
# This is the age field
age: 30
`,
			check: func(t *testing.T, merged []byte) {
				s := string(merged)
				assert.Contains(t, s, "# This is the age field")
				m := parseYAML(t, merged)
				assert.Equal(t, uint64(30), m["age"])
			},
		},
		{
			name:     "empty existing config gets all template keys",
			existing: "",
			template: `name: default
port: 3000
`,
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "default", m["name"])
				assert.Equal(t, uint64(3000), m["port"])
			},
		},
		{
			name: "empty template is no-op",
			existing: `name: alice
port: 8080
`,
			template: "",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "alice", m["name"])
				assert.Equal(t, uint64(8080), m["port"])
			},
		},
		{
			name: "type mismatch user scalar vs template mapping - user wins",
			existing: `server: simple-string
`,
			template: `server:
  host: localhost
  port: 9090
`,
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "simple-string", m["server"])
			},
		},
		{
			name: "type mismatch user mapping vs template scalar - user wins",
			existing: `server:
  host: localhost
  port: 9090
`,
			template: `server: simple-string
`,
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				srv, ok := m["server"].(map[string]any)
				require.True(t, ok, "server should remain a map")
				assert.Equal(t, "localhost", srv["host"])
			},
		},
		{
			name: "different key order no duplicates",
			existing: `b: 2
a: 1
`,
			template: `a: 10
b: 20
c: 3
`,
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, uint64(1), m["a"])
				assert.Equal(t, uint64(2), m["b"])
				assert.Equal(t, uint64(3), m["c"])
				// Ensure no duplicate keys in output
				count := strings.Count(string(merged), "a:")
				assert.Equal(t, 1, count, "key 'a' should appear exactly once")
				count = strings.Count(string(merged), "b:")
				assert.Equal(t, 1, count, "key 'b' should appear exactly once")
			},
		},
		{
			name:     "malformed existing YAML returns error",
			existing: ":\n  :\n[invalid yaml{{{",
			template: "name: default\n",
			wantErr:  true,
		},
		{
			name:     "malformed template YAML returns error",
			existing: "name: alice\n",
			template: ":\n  :\n[invalid yaml{{{",
			wantErr:  true,
		},
		{
			name: "inline comments on existing keys preserved",
			existing: `name: alice # this is the name
port: 8080 # server port
`,
			template: `name: default
port: 3000
age: 30
`,
			check: func(t *testing.T, merged []byte) {
				s := string(merged)
				assert.Contains(t, s, "# this is the name")
				assert.Contains(t, s, "# server port")
				m := parseYAML(t, merged)
				assert.Equal(t, "alice", m["name"])
				assert.Equal(t, uint64(8080), m["port"])
			},
		},
		{
			name:     "multiple new top-level keys appended",
			existing: "name: alice\n",
			template: `name: default
age: 30
city: nyc
debug: true
`,
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "alice", m["name"])
				assert.Equal(t, uint64(30), m["age"])
				assert.Equal(t, "nyc", m["city"])
				assert.Equal(t, true, m["debug"])
			},
		},
		{
			name:     "new nested section added entirely",
			existing: "name: alice\n",
			template: `name: default
database:
  host: db.local
  port: 5432
`,
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "alice", m["name"])
				assertDeepValue(t, m, []string{"database", "host"}, "db.local")
				assertDeepValue(t, m, []string{"database", "port"}, uint64(5432))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := MergeYAML([]byte(tc.existing), []byte(tc.template))
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			tc.check(t, merged)
		})
	}
}

func TestMergeWithPMGTemplate(t *testing.T) {
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

	// User comments preserved
	assert.Contains(t, raw, "# My PMG config")
	assert.Contains(t, raw, "# My custom trusted packages")

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
