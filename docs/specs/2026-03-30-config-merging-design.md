# Config Merging During Setup Install

**Issue:** [#114](https://github.com/safedep/pmg/issues/114)
**Date:** 2026-03-30

## Problem

When PMG's config template is updated with new keys/options, existing user configs
become stale. Currently, `pmg setup install` skips writing if a config file already
exists, so users never get new configuration options.

## Solution

Modify `WriteTemplateConfig()` to merge missing keys from the embedded config template
into the user's existing config file using YAML AST manipulation. The merge is silent,
non-interactive, and preserves all existing user content.

## Merge Rules

1. **Key exists in user config** - Always keep user's value and comments. Never overwrite.
2. **Key exists only in template** - Add to user's config with template's comments.
3. **Key exists only in user config** (removed/renamed in template) - Leave untouched.
4. **Nested key missing under existing parent** - Insert under that parent mapping.
5. **New top-level key** - Append at bottom of file.
6. **Malformed user config** - Fail with error, do not write.

No automatic migration for renamed keys (e.g., `experimental_proxy_mode` -> `proxy_mode`).
Both keys coexist; new PMG code reads the new key, old key is harmless.

## Architecture

### New Package: `config/merge/`

Isolates YAML AST merge logic from config handling. Independently testable.

#### `config/merge/merge.go`

Exports a single pure function:

```go
func MergeYAML(existing []byte, template []byte) ([]byte, error)
```

- Parses both inputs into AST using `goccy/go-yaml` with `ParseComments`
- Walks recursively, merges missing keys from template into existing
- Returns merged YAML bytes
- No file I/O — pure transformation

#### `config/merge/merge_test.go`

Comprehensive table-driven tests (TDD approach).

### Modified: `config/config.go`

`WriteTemplateConfig()` changes:

- Config file **does not exist** -> Write full template (current behavior, unchanged)
- Config file **exists** -> Read it, call `MergeYAML(existing, template)`, write result
- Config file **unparseable** -> Return error, do not write

No changes to: Viper loading, CLI flags, runtime config, sandbox policy, or command logic.
The merge only runs during `pmg setup install`.

## Merge Algorithm

1. Parse both files with `goccy/go-yaml` parser (`ParseComments` option)
2. Extract root `MappingNode` from both ASTs
3. For each key in template's mapping:
   - **Not in user's mapping** -> Append the node (with comments) to user's mapping
   - **In both, both values are mappings** -> Recurse into the nested mapping
   - **In both, different types or scalar/sequence** -> Skip (user wins)
4. Serialize user's AST back to bytes

Key ordering in user's config is irrelevant — a map of existing keys is built before
walking the template, so no duplicates are possible regardless of order.

### Comment Handling

- Existing user comments are never modified (we never touch existing nodes)
- New keys from template carry their head comments, line comments, and foot comments
- Blank line inserted before newly appended top-level keys for readability

### Edge Cases

| Scenario | Behavior |
|----------|----------|
| Empty user config (valid YAML, no keys) | Gets all template keys |
| Empty template | No-op, user config unchanged |
| Deeply nested new keys (3+ levels) | Inserted under correct parent via recursion |
| Type mismatch (scalar vs mapping) | User wins, no merge into that subtree |
| Config file missing | Write full template |
| Unparseable config YAML | Return error, no write |
| Different key ordering | Works — lookup is map-based, no duplicates |

## Dependencies

- [`goccy/go-yaml`](https://github.com/goccy/go-yaml) — YAML parser with AST access and comment preservation

## Entry Point

Only triggered via `pmg setup install`. No new commands or flags introduced.
Future enhancements (diff display, `pmg setup update`, interactive mode) can build
on this foundation incrementally.
