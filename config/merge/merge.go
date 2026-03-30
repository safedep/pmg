package merge

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// MergeYAML merges missing keys from template into existing YAML config.
// It preserves all existing user values, comments, and formatting.
// Only keys present in template but absent in existing are added.
func MergeYAML(existing []byte, template []byte) ([]byte, error) {
	existingEmpty := isEmptyYAML(existing)
	templateEmpty := isEmptyYAML(template)

	// Rule 8: empty template → return existing unchanged
	if templateEmpty {
		return existing, nil
	}

	// Rule 7: empty existing → return full template
	if existingEmpty {
		// Validate template parses
		_, err := parser.ParseBytes(template, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template YAML: %w", err)
		}
		return template, nil
	}

	// Parse both files
	existingFile, err := parser.ParseBytes(existing, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse existing YAML: %w", err)
	}

	templateFile, err := parser.ParseBytes(template, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template YAML: %w", err)
	}

	// Extract root mapping nodes
	existingMap, err := getRootMapping(existingFile)
	if err != nil {
		return nil, fmt.Errorf("existing config: %w", err)
	}

	templateMap, err := getRootMapping(templateFile)
	if err != nil {
		return nil, fmt.Errorf("template config: %w", err)
	}

	// Recursively merge
	mergeMapping(existingMap, templateMap)

	// Serialize back
	return []byte(existingFile.String() + "\n"), nil
}

// isEmptyYAML checks if YAML content is empty or whitespace/comments only.
func isEmptyYAML(data []byte) bool {
	s := strings.TrimSpace(string(data))
	if s == "" {
		return true
	}
	// Check if it's only comments
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return false
		}
	}
	return true
}

// getRootMapping extracts the root MappingNode from a parsed YAML file.
func getRootMapping(file *ast.File) (*ast.MappingNode, error) {
	if len(file.Docs) == 0 {
		return nil, fmt.Errorf("no documents found")
	}
	doc := file.Docs[0]
	if doc.Body == nil {
		return nil, fmt.Errorf("empty document body")
	}
	mapping, ok := doc.Body.(*ast.MappingNode)
	if !ok {
		return nil, fmt.Errorf("root is not a mapping node, got %T", doc.Body)
	}
	return mapping, nil
}

// mergeMapping recursively merges keys from tmpl into target.
// Keys that exist in target are never overwritten.
// Keys only in tmpl are appended to target.
func mergeMapping(target, tmpl *ast.MappingNode) {
	// Build lookup of existing keys
	existingKeys := make(map[string]int, len(target.Values))
	for i, mv := range target.Values {
		existingKeys[mv.Key.String()] = i
	}

	for _, tmplMV := range tmpl.Values {
		key := tmplMV.Key.String()
		idx, exists := existingKeys[key]
		if !exists {
			// Key not in target — append it with its comments
			// Adjust column to match target's indentation
			targetCol := targetStartColumn(target)
			tmplCol := tmplMV.Key.GetToken().Position.Column
			colDiff := targetCol - tmplCol
			if colDiff != 0 {
				tmplMV.AddColumn(colDiff)
			}
			target.Values = append(target.Values, tmplMV)
		} else {
			// Key exists in both — recurse if both are mappings
			existingValue := target.Values[idx].Value
			tmplValue := tmplMV.Value

			existingMapping, existingIsMap := existingValue.(*ast.MappingNode)
			tmplMapping, tmplIsMap := tmplValue.(*ast.MappingNode)

			if existingIsMap && tmplIsMap {
				// Both are mappings — recurse
				mergeMapping(existingMapping, tmplMapping)
			}
			// Otherwise user wins (rule 5, 9)
		}
	}
}

// targetStartColumn returns the column of the first key in a mapping,
// or 1 if the mapping has no values yet.
func targetStartColumn(m *ast.MappingNode) int {
	if len(m.Values) > 0 {
		return m.Values[0].Key.GetToken().Position.Column
	}
	return 1
}

