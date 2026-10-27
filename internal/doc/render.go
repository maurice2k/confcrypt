package doc

import (
	"bytes"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/maurice2k/confcrypt/internal/format"
)

// RenderJSON renders any node (of any format) as JSON with two-space
// indentation, keys in document order and no HTML escaping. A scalar value
// of integer or float type that is not a valid JSON number (for example a
// YAML hex integer) is rendered as a string.
func RenderJSON(n Node) ([]byte, error) {
	return RenderJSONIndented(n, 0)
}

// RenderJSONIndented renders like RenderJSON with every line after the
// first indented by level steps, for embedding in a larger document.
func RenderJSONIndented(n Node, level int) ([]byte, error) {
	var buf bytes.Buffer
	if err := renderJSONNode(&buf, n, level); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func renderJSONNode(buf *bytes.Buffer, n Node, level int) error {
	if n == nil {
		buf.WriteString("null")
		return nil
	}
	n = n.Target()
	switch n.Kind() {
	case Scalar:
		typ := n.Type()
		if (typ == format.TypeInt || typ == format.TypeFloat) && !jsonNumberRe.MatchString(n.Value()) {
			typ = format.TypeString
		}
		if typ == format.TypeBool {
			switch strings.ToLower(n.Value()) {
			case "true", "false":
			default:
				typ = format.TypeString
			}
		}
		return writeJSONScalar(buf, n.Value(), typ)

	case Mapping:
		if n.Len() == 0 {
			buf.WriteString("{}")
			return nil
		}
		buf.WriteString("{\n")
		for i := 0; i < n.Len(); i++ {
			if i > 0 {
				buf.WriteString(",\n")
			}
			buf.WriteString(strings.Repeat("  ", level+1))
			if err := writeJSONString(buf, n.Key(i)); err != nil {
				return err
			}
			buf.WriteString(": ")
			if err := renderJSONNode(buf, n.Item(i), level+1); err != nil {
				return err
			}
		}
		buf.WriteString("\n")
		buf.WriteString(strings.Repeat("  ", level))
		buf.WriteString("}")
		return nil

	default:
		if n.Len() == 0 {
			buf.WriteString("[]")
			return nil
		}
		buf.WriteString("[\n")
		for i := 0; i < n.Len(); i++ {
			if i > 0 {
				buf.WriteString(",\n")
			}
			buf.WriteString(strings.Repeat("  ", level+1))
			if err := renderJSONNode(buf, n.Item(i), level+1); err != nil {
				return err
			}
		}
		buf.WriteString("\n")
		buf.WriteString(strings.Repeat("  ", level))
		buf.WriteString("]")
		return nil
	}
}

// RenderYAML renders a node as a YAML document. YAML nodes are rendered
// directly, keeping their comments and styles; nodes of other formats are
// converted first.
func RenderYAML(n Node) ([]byte, error) {
	var y *yaml.Node
	if n != nil {
		n = n.Target()
		y = YAML(n)
		if y == nil {
			y = toYAMLNode(n)
		}
	}
	if y == nil {
		y = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(y); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func toYAMLNode(n Node) *yaml.Node {
	n = n.Target()
	switch n.Kind() {
	case Mapping:
		y := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for i := 0; i < n.Len(); i++ {
			y.Content = append(y.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: n.Key(i)},
				toYAMLNode(n.Item(i)))
		}
		return y
	case Sequence:
		y := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for i := 0; i < n.Len(); i++ {
			y.Content = append(y.Content, toYAMLNode(n.Item(i)))
		}
		return y
	default:
		y := &yaml.Node{Kind: yaml.ScalarNode, Value: n.Value()}
		if tag := n.Tag(); tag != "" {
			y.Tag = tag
		} else {
			y.Tag = yamlTagFor(n.Type())
		}
		if y.Tag == "!!null" {
			y.Value = "null"
		}
		return y
	}
}
