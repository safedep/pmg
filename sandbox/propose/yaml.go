package propose

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/safedep/pmg/sandbox"
	"gopkg.in/yaml.v3"
)

// RenderBlock writes the two outbound lists at two-space indent, the shape
// the built-in profiles use.
func RenderBlock(network sandbox.NetworkPolicy) []byte {
	var b bytes.Buffer
	b.WriteString("network:\n")
	for _, list := range []struct {
		key   string
		rules []string
	}{{"allow_outbound", network.AllowOutbound}, {"deny_outbound", network.DenyOutbound}} {
		fmt.Fprintf(&b, "  %s:", list.key)
		if len(list.rules) == 0 {
			b.WriteString(" []\n")
			continue
		}
		b.WriteString("\n")
		for _, rule := range list.rules {
			fmt.Fprintf(&b, "    - %s\n", yamlRule(rule))
		}
	}
	return b.Bytes()
}

// yamlRule writes a network rule as the built-in profiles do: plain, and
// quoted only when YAML would read the first character as an alias or a
// flow collection, as in "*:*".
func yamlRule(rule string) string {
	if rule == "" || strings.ContainsAny(rule[:1], "*&[{!|>'\"%@`") || strings.ContainsAny(rule, " #") {
		return fmt.Sprintf("%q", rule)
	}
	return rule
}

// SetBlock replaces the allow_outbound and deny_outbound lists of the
// network block in doc and leaves every other node as it is. Comments
// survive, because the edit is on the YAML node tree. A network key with
// no mapping, such as the `network:` of a skeleton, gets one.
func SetBlock(doc []byte, network sandbox.NetworkPolicy) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("parse profile: the document is not a mapping")
	}
	top := root.Content[0]
	networkNode := mappingValue(top, "network")
	switch {
	case networkNode == nil:
		networkNode = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		top.Content = append(top.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "network"}, networkNode)
	case networkNode.Kind != yaml.MappingNode:
		*networkNode = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Anchor: networkNode.Anchor}
	}
	setSequence(networkNode, "allow_outbound", network.AllowOutbound)
	setSequence(networkNode, "deny_outbound", network.DenyOutbound)

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, fmt.Errorf("encode profile: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode profile: %w", err)
	}
	return out.Bytes(), nil
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

// setSequence sets key to values. An anchor on the old node stays, so an
// alias elsewhere in the document still resolves.
func setSequence(mapping *yaml.Node, key string, values []string) {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, v := range values {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
	}
	if existing := mappingValue(mapping, key); existing != nil {
		seq.Anchor = existing.Anchor
		*existing = *seq
		return
	}
	mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, seq)
}
