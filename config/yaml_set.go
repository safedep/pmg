package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
)

// SetConfigValue updates a config value in the YAML config file on disk.
// It does not update the in-memory config or viper state. Callers that need
// the updated value must re-initialize the config after calling this function.
func SetConfigValue(key, value string) error {
	configPath, err := configFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

	if err := ensureConfigFileExists(configPath); err != nil {
		return err
	}

	fi, err := os.Stat(configPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %w", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	result, err := setValueInYAML(data, key, value)
	if err != nil {
		return fmt.Errorf("failed to set config value: %w", err)
	}

	if err := os.WriteFile(configPath, result, fi.Mode()); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func GetConfigValue(key string) (any, error) {
	if key == "" {
		return nil, fmt.Errorf("key cannot be empty")
	}

	v := Get().viper
	if v == nil {
		return nil, fmt.Errorf("config not initialized")
	}

	if !v.IsSet(key) {
		return nil, fmt.Errorf("unknown config key: %s", key)
	}

	return v.Get(key), nil
}

func setValueInYAML(data []byte, key, value string) ([]byte, error) {
	if key == "" {
		return nil, fmt.Errorf("key cannot be empty")
	}

	file, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if len(file.Docs) == 0 {
		return nil, fmt.Errorf("no documents found in YAML")
	}

	root, ok := file.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return nil, fmt.Errorf("root is not a mapping node")
	}

	segments := strings.Split(key, ".")
	if err := setValueAtPath(root, segments, value); err != nil {
		return nil, err
	}

	return []byte(file.String()), nil
}

func setValueAtPath(node *ast.MappingNode, segments []string, value string) error {
	if len(segments) == 0 {
		return fmt.Errorf("key cannot be empty")
	}

	target := segments[0]
	for _, mv := range node.Values {
		if mv.Key.String() != target {
			continue
		}

		if len(segments) == 1 {
			return replaceScalarValue(mv, value)
		}

		childMapping, ok := mv.Value.(*ast.MappingNode)
		if !ok {
			return fmt.Errorf("key not found: intermediate key %q is not a mapping", target)
		}
		return setValueAtPath(childMapping, segments[1:], value)
	}

	return fmt.Errorf("key not found: %q", target)
}

func replaceScalarValue(mv *ast.MappingValueNode, value string) error {
	if mv.Value == nil {
		return fmt.Errorf("cannot set value: %q has no existing value", mv.Key.String())
	}

	pos := mv.Value.GetToken().Position

	switch mv.Value.(type) {
	case *ast.MappingNode:
		return fmt.Errorf("cannot set value on non-scalar node: %q is a mapping", mv.Key.String())
	case *ast.SequenceNode:
		return fmt.Errorf("cannot set value on non-scalar node: %q is a sequence", mv.Key.String())
	case *ast.StringNode:
		newNode, err := createStringNode(value, pos)
		if err != nil {
			return err
		}
		return mv.Replace(newNode)
	case *ast.BoolNode:
		if value != "true" && value != "false" {
			return fmt.Errorf("invalid value %q for %q: expected true or false", value, mv.Key.String())
		}
	case *ast.IntegerNode:
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return fmt.Errorf("invalid value %q for %q: expected an integer", value, mv.Key.String())
		}
	default:
		return fmt.Errorf("unsupported node type for key %q: %T", mv.Key.String(), mv.Value)
	}

	newNode, err := createScalarNode(value, pos)
	if err != nil {
		return err
	}
	return mv.Replace(newNode)
}

func createStringNode(value string, pos *token.Position) (ast.Node, error) {
	newPos := &token.Position{
		Line:   pos.Line,
		Column: pos.Column,
		Offset: pos.Offset,
	}

	if needsQuoting(value) {
		tk := token.New(value, value, newPos)
		tk.Type = token.DoubleQuoteType
		return ast.String(tk), nil
	}

	tk := token.String(value, value, newPos)
	return ast.String(tk), nil
}

func needsQuoting(value string) bool {
	if value == "true" || value == "false" || value == "null" ||
		value == "True" || value == "False" || value == "yes" || value == "no" {
		return true
	}
	if _, err := strconv.ParseInt(value, 10, 64); err == nil {
		return true
	}
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		return true
	}
	return false
}

func createScalarNode(value string, pos *token.Position) (ast.Node, error) {
	newPos := &token.Position{
		Line:   pos.Line,
		Column: pos.Column,
		Offset: pos.Offset,
	}

	if value == "true" || value == "false" {
		tk := token.New(value, value, newPos)
		return ast.Bool(tk), nil
	}

	if _, err := strconv.ParseInt(value, 10, 64); err == nil {
		tk := token.New(value, value, newPos)
		return ast.Integer(tk), nil
	}

	tk := token.String(value, value, newPos)
	return ast.String(tk), nil
}

func ensureConfigFileExists(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat config file %q: %w", path, err)
	}
	return WriteTemplateConfig()
}
