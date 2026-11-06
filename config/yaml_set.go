package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	goyaml "github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/internal/platform"
)

// SetConfigValue updates a config value in the YAML config file on disk.
// It does not update the in-memory config or viper state. Callers that need
// the updated value must re-initialize the config after calling this function.
func SetConfigValue(key, value string) error {
	if globalConfig.IsManaged() {
		return NewManagedConfigError()
	}

	configPath, err := userConfigFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

	if err := ensureConfigFileExists(configPath); err != nil {
		return err
	}

	err = setConfigValueInFile(configPath, key, value)
	if !errors.Is(err, errKeyNotFound) || !templateHasKey(key) {
		return err
	}

	// A config file that an older PMG wrote can miss a whole section of the
	// template, such as cloud. pmg setup install merges the template into the
	// file. Do the same merge here, so the user does not have to run setup,
	// which also writes shell aliases and PATH shims.
	if err := mergeTemplateIntoFile(configPath); err != nil {
		return fmt.Errorf("failed to add the missing keys of the template: %w", err)
	}
	return setConfigValueInFile(configPath, key, value)
}

var errKeyNotFound = errors.New("key not found")

func templateHasKey(key string) bool {
	v, err := newFileViper("")
	return err == nil && v.IsSet(key)
}

// SetSystemConfigValue updates a value in the managed config, the file a
// root daemon and every user obey. Only root may call it. The file is
// created from the template when it is missing, through the same ownership
// and mode checks as `pmg setup install --system`.
func SetSystemConfigValue(key, value string) error {
	if err := RequireSystemScope("pmg config set --system"); err != nil {
		return err
	}
	configPath, err := EnsureSystemConfigFile()
	if err != nil {
		return err
	}
	return setConfigValueInFile(configPath, key, value)
}

// EnsureSystemConfigFile creates the managed config from the template when
// it is missing and returns its path. An existing file is checked, not
// merged with the template. A managed config may hold only the keys an
// administrator set, and a merge would freeze the other defaults into it.
func EnsureSystemConfigFile() (string, error) {
	path := globalConfigFilePath()
	if path == "" {
		return "", fmt.Errorf("system config is not supported on %s", platform.OSName())
	}
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return path, WriteSystemTemplateConfig()
	}
	if err != nil {
		return "", fmt.Errorf("failed to stat managed config %q: %w", path, err)
	}
	return path, requireTrustedManagedFile(path)
}

// GetSystemConfigValue reads a key from the managed config file alone, with
// the template as the base for keys the file does not set. It reads the
// file as any user can, and it ignores the environment.
func GetSystemConfigValue(key string) (any, error) {
	if key == "" {
		return nil, fmt.Errorf("key cannot be empty")
	}
	path := globalConfigFilePath()
	if path == "" {
		return nil, fmt.Errorf("system config is not supported on %s", platform.OSName())
	}
	v, err := newFileViper(path)
	if err != nil {
		return nil, err
	}
	if !v.IsSet(key) {
		return nil, fmt.Errorf("unknown config key: %s", key)
	}
	return v.Get(key), nil
}

// mergeTemplateIntoFile merges the template into the config file, as pmg
// setup install does. The merge keeps a key that the file has, also when its
// value is empty, so a section such as "cloud:" with no keys would stay
// empty. The merge drops such a top-level key first, and the section of the
// template takes its place.
func mergeTemplateIntoFile(configPath string) error {
	fi, err := os.Stat(configPath)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %w", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	data, err = dropEmptyTopLevelKeys(data)
	if err != nil {
		return err
	}
	merged, err := utils.MergeYAML(data, []byte(templateConfig))
	if err != nil {
		return fmt.Errorf("failed to merge config: %w", err)
	}
	if err := os.WriteFile(configPath, merged, fi.Mode()); err != nil {
		return fmt.Errorf("failed to write merged config: %w", err)
	}
	return nil
}

func dropEmptyTopLevelKeys(data []byte) ([]byte, error) {
	file, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	if len(file.Docs) == 0 {
		return data, nil
	}
	root, ok := file.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return data, nil
	}

	kept := root.Values[:0]
	for _, mv := range root.Values {
		if _, empty := mv.Value.(*ast.NullNode); !empty {
			kept = append(kept, mv)
		}
	}
	if len(kept) == len(root.Values) {
		return data, nil
	}
	root.Values = kept
	return []byte(file.String()), nil
}

func setConfigValueInFile(configPath, key, value string) error {
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
	if err := setValueAtPath(root, segments, value, templateScalarDefault(key)); err != nil {
		return nil, err
	}

	return []byte(file.String()), nil
}

// templateScalarDefault returns the template value of a scalar key. A config
// file that an older PMG wrote does not hold a key that a newer template adds,
// such as cloud.policy. pmg config set adds such a key with this value as the
// type, and then sets it.
func templateScalarDefault(key string) any {
	v, err := newFileViper("")
	if err != nil || !v.IsSet(key) {
		return nil
	}
	switch value := v.Get(key); value.(type) {
	case bool, int, string:
		return value
	default:
		return nil
	}
}

func setValueAtPath(node *ast.MappingNode, segments []string, value string, templateDefault any) error {
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
		if _, empty := mv.Value.(*ast.NullNode); empty {
			return fmt.Errorf("%w: intermediate key %q has no value", errKeyNotFound, target)
		}
		if !ok {
			return fmt.Errorf("key not found: intermediate key %q is not a mapping", target)
		}
		return setValueAtPath(childMapping, segments[1:], value, templateDefault)
	}

	if len(segments) == 1 && templateDefault != nil && len(node.Values) > 0 {
		mv, err := newMappingValue(target, templateDefault, node.Values[0].Key.GetToken().Position.Column)
		if err != nil {
			return err
		}
		node.Values = append(node.Values, mv)
		return replaceScalarValue(mv, value)
	}

	return fmt.Errorf("%w: %q", errKeyNotFound, target)
}

// newMappingValue returns the mapping value "key: value" at column, the
// column of the other keys of its mapping.
func newMappingValue(key string, value any, column int) (*ast.MappingValueNode, error) {
	snippet, err := goyaml.Marshal(map[string]any{key: value})
	if err != nil {
		return nil, fmt.Errorf("failed to add key %q: %w", key, err)
	}
	file, err := parser.ParseBytes(snippet, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to add key %q: %w", key, err)
	}
	mapping, ok := file.Docs[0].Body.(*ast.MappingNode)
	if !ok || len(mapping.Values) != 1 {
		return nil, fmt.Errorf("failed to add key %q", key)
	}
	mv := mapping.Values[0]
	mv.AddColumn(column - 1)
	return mv, nil
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
	if value == "" {
		return true
	}
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
