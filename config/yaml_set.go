package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"github.com/spf13/viper"
)

func SetValueInYAML(data []byte, key, value string) ([]byte, error) {
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
	switch mv.Value.(type) {
	case *ast.MappingNode:
		return fmt.Errorf("cannot set value on non-scalar node: %q is a mapping", mv.Key.String())
	case *ast.SequenceNode:
		return fmt.Errorf("cannot set value on non-scalar node: %q is a sequence", mv.Key.String())
	}

	newNode, err := createScalarNode(value, mv.Value.GetToken().Position)
	if err != nil {
		return err
	}
	return mv.Replace(newNode)
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

func SetConfigValue(key, value string) error {
	configPath, err := configFilePath()
	if err != nil {
		return fmt.Errorf("failed to get config file path: %w", err)
	}

	if err := ensureConfigFileExists(configPath); err != nil {
		return err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	result, err := SetValueInYAML(data, key, value)
	if err != nil {
		return fmt.Errorf("failed to set config value: %w", err)
	}

	if err := os.WriteFile(configPath, result, 0o644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func ensureConfigFileExists(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return WriteTemplateConfig()
}

func GetConfigValue(key string) (any, error) {
	configPath, err := configFilePath()
	if err != nil {
		return nil, fmt.Errorf("failed to get config file path: %w", err)
	}

	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("PMG")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	if err := v.ReadConfig(strings.NewReader(templateConfig)); err != nil {
		return nil, fmt.Errorf("failed to load default config: %w", err)
	}

	if _, statErr := os.Stat(configPath); statErr == nil {
		v.SetConfigFile(configPath)
		if err := v.MergeInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	if !v.IsSet(key) {
		return nil, fmt.Errorf("unknown config key: %s", key)
	}

	return v.Get(key), nil
}
