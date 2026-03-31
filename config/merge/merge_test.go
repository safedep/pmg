package merge

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseYAML(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, yaml.Unmarshal(data, &m), "failed to parse YAML result")
	return m
}

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
		name    string
		dest    string
		source  string
		check   func(t *testing.T, merged []byte)
		wantErr bool
	}{
		{
			name:   "new top-level key appended",
			dest:   "name: alice\n",
			source: "name: default\nage: 30\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "alice", m["name"])
				assert.Equal(t, uint64(30), m["age"])
			},
		},
		{
			name:   "existing value never overwritten",
			dest:   "port: 8080\n",
			source: "port: 3000\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, uint64(8080), m["port"])
			},
		},
		{
			name:   "nested key added under existing parent",
			dest:   "server:\n  host: localhost\n",
			source: "server:\n  host: 0.0.0.0\n  port: 9090\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assertDeepValue(t, m, []string{"server", "host"}, "localhost")
				assertDeepValue(t, m, []string{"server", "port"}, uint64(9090))
			},
		},
		{
			name:   "deeply nested new keys 3+ levels",
			dest:   "a:\n  b:\n    c: 1\n",
			source: "a:\n  b:\n    c: 99\n    d: 2\n  e:\n    f: 3\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assertDeepValue(t, m, []string{"a", "b", "c"}, uint64(1))
				assertDeepValue(t, m, []string{"a", "b", "d"}, uint64(2))
				assertDeepValue(t, m, []string{"a", "e", "f"}, uint64(3))
			},
		},
		{
			name:   "user-only keys preserved",
			dest:   "custom: myvalue\nname: alice\n",
			source: "name: default\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "myvalue", m["custom"])
				assert.Equal(t, "alice", m["name"])
			},
		},
		{
			name:   "user comments preserved",
			dest:   "# User's important comment\nname: alice\n",
			source: "name: default\nage: 30\n",
			check: func(t *testing.T, merged []byte) {
				assert.Contains(t, string(merged), "# User's important comment")
				m := parseYAML(t, merged)
				assert.Equal(t, "alice", m["name"])
				assert.Equal(t, uint64(30), m["age"])
			},
		},
		{
			name:   "source comments come with new keys",
			dest:   "name: alice\n",
			source: "name: default\n# This is the age field\nage: 30\n",
			check: func(t *testing.T, merged []byte) {
				assert.Contains(t, string(merged), "# This is the age field")
				m := parseYAML(t, merged)
				assert.Equal(t, uint64(30), m["age"])
			},
		},
		{
			name:   "empty dest gets all source keys",
			dest:   "",
			source: "name: default\nport: 3000\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "default", m["name"])
				assert.Equal(t, uint64(3000), m["port"])
			},
		},
		{
			name:   "empty source is no-op",
			dest:   "name: alice\nport: 8080\n",
			source: "",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "alice", m["name"])
				assert.Equal(t, uint64(8080), m["port"])
			},
		},
		{
			name:   "type mismatch user scalar vs source mapping - dest wins",
			dest:   "server: simple-string\n",
			source: "server:\n  host: localhost\n  port: 9090\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "simple-string", m["server"])
			},
		},
		{
			name:   "type mismatch user mapping vs source scalar - dest wins",
			dest:   "server:\n  host: localhost\n  port: 9090\n",
			source: "server: simple-string\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				srv, ok := m["server"].(map[string]any)
				require.True(t, ok, "server should remain a map")
				assert.Equal(t, "localhost", srv["host"])
			},
		},
		{
			name:   "different key order no duplicates",
			dest:   "b: 2\na: 1\n",
			source: "a: 10\nb: 20\nc: 3\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, uint64(1), m["a"])
				assert.Equal(t, uint64(2), m["b"])
				assert.Equal(t, uint64(3), m["c"])
				assert.Equal(t, 1, strings.Count(string(merged), "a:"))
				assert.Equal(t, 1, strings.Count(string(merged), "b:"))
			},
		},
		{
			name:    "malformed dest returns error",
			dest:    ":\n  :\n[invalid yaml{{{",
			source:  "name: default\n",
			wantErr: true,
		},
		{
			name:    "malformed source returns error",
			dest:    "name: alice\n",
			source:  ":\n  :\n[invalid yaml{{{",
			wantErr: true,
		},
		{
			name:   "inline comments on existing keys preserved",
			dest:   "name: alice # this is the name\nport: 8080 # server port\n",
			source: "name: default\nport: 3000\nage: 30\n",
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
			name:   "multiple new top-level keys appended",
			dest:   "name: alice\n",
			source: "name: default\nage: 30\ncity: nyc\ndebug: true\n",
			check: func(t *testing.T, merged []byte) {
				m := parseYAML(t, merged)
				assert.Equal(t, "alice", m["name"])
				assert.Equal(t, uint64(30), m["age"])
				assert.Equal(t, "nyc", m["city"])
				assert.Equal(t, true, m["debug"])
			},
		},
		{
			name:   "new nested section added entirely",
			dest:   "name: alice\n",
			source: "name: default\ndatabase:\n  host: db.local\n  port: 5432\n",
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
			merged, err := MergeYAML([]byte(tc.dest), []byte(tc.source))
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
	assert.Contains(t, raw, "# My PMG config")
	assert.Contains(t, raw, "# My custom trusted packages")

	parsed := parseYAML(t, result)

	assert.Equal(t, false, parsed["transitive"])
	assert.Equal(t, uint64(10), parsed["transitive_depth"])
	assert.Equal(t, "verbose", parsed["verbosity"])
	assert.Equal(t, false, parsed["proxy_mode"])

	assert.Equal(t, false, parsed["include_dev_dependencies"])
	assert.Equal(t, false, parsed["paranoid"])
	assert.Equal(t, false, parsed["skip_event_logging"])
	assert.Equal(t, uint64(7), parsed["event_log_retention_days"])

	sandbox, ok := parsed["sandbox"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, sandbox["enabled"])
	assert.Equal(t, true, sandbox["enforce_always"])
	assert.NotNil(t, sandbox["policy_templates"])

	policies, ok := sandbox["policies"].(map[string]any)
	require.True(t, ok)
	npm, ok := policies["npm"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, false, npm["enabled"])
	assert.NotNil(t, policies["pnpm"])
}

func BenchmarkMergeYAML(b *testing.B) {
	dest := []byte(`transitive: false
transitive_depth: 10
verbosity: verbose
proxy_mode: false
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
`)

	source := []byte(`transitive: true
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
    pip:
      enabled: true
      profile: pypi-restrictive
`)

	b.ResetTimer()
	for b.Loop() {
		_, err := MergeYAML(dest, source)
		if err != nil {
			b.Fatal(err)
		}
	}
}
