package merge

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// MergeYAML merges missing keys from source into dest while preserving
// all existing dest values, comments, and formatting.
func MergeYAML(dest []byte, source []byte) ([]byte, error) {
	destEmpty := isEmptyYAML(dest)
	sourceEmpty := isEmptyYAML(source)

	if sourceEmpty {
		return dest, nil
	}

	if destEmpty {
		if _, err := parser.ParseBytes(source, parser.ParseComments); err != nil {
			return nil, fmt.Errorf("failed to parse source YAML: %w", err)
		}
		return source, nil
	}

	destFile, err := parser.ParseBytes(dest, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dest YAML: %w", err)
	}

	sourceFile, err := parser.ParseBytes(source, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse source YAML: %w", err)
	}

	destMap, err := getRootMapping(destFile)
	if err != nil {
		return nil, fmt.Errorf("dest: %w", err)
	}

	sourceMap, err := getRootMapping(sourceFile)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}

	mergeMappings(destMap, sourceMap)

	return []byte(destFile.String() + "\n"), nil
}

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

// mergeMappings recursively appends keys from source that are missing in dest.
// When a key exists in both and both values are mappings, it recurses.
// Otherwise dest's value wins.
func mergeMappings(dest, source *ast.MappingNode) {
	existing := make(map[string]int, len(dest.Values))
	for i, mv := range dest.Values {
		existing[mv.Key.String()] = i
	}

	for _, srcMV := range source.Values {
		key := srcMV.Key.String()
		idx, found := existing[key]
		if !found {
			destCol := startColumn(dest)
			srcCol := srcMV.Key.GetToken().Position.Column
			if colDiff := destCol - srcCol; colDiff != 0 {
				srcMV.AddColumn(colDiff)
			}
			dest.Values = append(dest.Values, srcMV)
			continue
		}

		destMapping, destOk := dest.Values[idx].Value.(*ast.MappingNode)
		srcMapping, srcOk := srcMV.Value.(*ast.MappingNode)
		if destOk && srcOk {
			mergeMappings(destMapping, srcMapping)
		}
	}
}

func startColumn(m *ast.MappingNode) int {
	if len(m.Values) > 0 {
		return m.Values[0].Key.GetToken().Position.Column
	}
	return 1
}
