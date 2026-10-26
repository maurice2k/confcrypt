package doc

import (
	"gopkg.in/yaml.v3"

	"github.com/maurice2k/confcrypt/internal/format"
)

// yamlNode adapts a yaml.v3 node tree to Node. Comments, styles, anchors
// and tags stay on the underlying nodes, so marshalling the tree after
// mutation preserves them.
type yamlNode struct {
	n *yaml.Node
}

// FromYAML wraps a yaml.v3 node. A document node is unwrapped to its root
// content; an empty document yields nil.
func FromYAML(n *yaml.Node) Node {
	if n == nil || n.Kind == 0 {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		n = n.Content[0]
	}
	return &yamlNode{n: n}
}

// YAML returns the underlying yaml.v3 node of a node created by FromYAML or
// one of the NewYAML* constructors, or nil for nodes of other formats.
func YAML(n Node) *yaml.Node {
	if y, ok := n.(*yamlNode); ok {
		return y.n
	}
	return nil
}

// NewYAMLScalar creates a detached scalar node.
func NewYAMLScalar(value string, typ format.ValueType, tag string) Node {
	y := &yamlNode{n: &yaml.Node{Kind: yaml.ScalarNode}}
	y.SetScalar(value, typ, tag)
	return y
}

// NewYAMLMapping creates a detached empty mapping node.
func NewYAMLMapping() Node {
	return &yamlNode{n: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}}
}

// NewYAMLSequence creates a detached empty sequence node.
func NewYAMLSequence() Node {
	return &yamlNode{n: &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}}
}

func (y *yamlNode) Kind() Kind {
	switch y.n.Kind {
	case yaml.MappingNode:
		return Mapping
	case yaml.SequenceNode:
		return Sequence
	case yaml.AliasNode:
		if y.n.Alias != nil {
			return y.Target().Kind()
		}
		return Scalar
	default:
		return Scalar
	}
}

func (y *yamlNode) IsAlias() bool {
	return y.n.Kind == yaml.AliasNode && y.n.Alias != nil
}

func (y *yamlNode) Target() Node {
	if y.IsAlias() {
		return FromYAML(y.n.Alias)
	}
	return y
}

func (y *yamlNode) Value() string {
	return y.n.Value
}

// Type derives the portable type from the resolved YAML tag.
func (y *yamlNode) Type() format.ValueType {
	switch y.n.Tag {
	case "!!int":
		return format.TypeInt
	case "!!float":
		return format.TypeFloat
	case "!!bool":
		return format.TypeBool
	case "!!null":
		return format.TypeNull
	default:
		return format.TypeString
	}
}

// Tag returns tags that cannot be reconstructed from Type (timestamps,
// binary scalars, application-specific tags) and "" for the core ones.
func (y *yamlNode) Tag() string {
	switch y.n.Tag {
	case "", "!!str", "!!int", "!!float", "!!bool", "!!null":
		return ""
	default:
		return y.n.Tag
	}
}

func yamlTagFor(typ format.ValueType) string {
	switch typ {
	case format.TypeInt:
		return "!!int"
	case format.TypeFloat:
		return "!!float"
	case format.TypeBool:
		return "!!bool"
	case format.TypeNull:
		return "!!null"
	default:
		return "!!str"
	}
}

// SetScalar sets value and tag and resets the style so the encoder picks a
// valid quoting for the new content.
func (y *yamlNode) SetScalar(value string, typ format.ValueType, tag string) {
	y.n.Kind = yaml.ScalarNode
	y.n.Content = nil
	y.n.Alias = nil
	y.n.Value = value
	if tag != "" {
		y.n.Tag = tag
	} else {
		y.n.Tag = yamlTagFor(typ)
	}
	y.n.Style = 0
}

func (y *yamlNode) Len() int {
	switch y.n.Kind {
	case yaml.MappingNode:
		return len(y.n.Content) / 2
	case yaml.SequenceNode:
		return len(y.n.Content)
	default:
		return 0
	}
}

func (y *yamlNode) Key(i int) string {
	if y.n.Kind != yaml.MappingNode || i < 0 || 2*i >= len(y.n.Content) {
		return ""
	}
	return y.n.Content[2*i].Value
}

func (y *yamlNode) Item(i int) Node {
	switch y.n.Kind {
	case yaml.MappingNode:
		if i < 0 || 2*i+1 >= len(y.n.Content) {
			return nil
		}
		return FromYAML(y.n.Content[2*i+1])
	case yaml.SequenceNode:
		if i < 0 || i >= len(y.n.Content) {
			return nil
		}
		return FromYAML(y.n.Content[i])
	default:
		return nil
	}
}

func (y *yamlNode) Get(key string) (Node, bool) {
	if y.n.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(y.n.Content); i += 2 {
		if y.n.Content[i].Value == key {
			return FromYAML(y.n.Content[i+1]), true
		}
	}
	return nil, false
}

func (y *yamlNode) Set(key string, value Node) error {
	if y.n.Kind != yaml.MappingNode {
		return ErrUnsupported
	}
	v, ok := value.(*yamlNode)
	if !ok {
		return ErrWrongDocument
	}
	for i := 0; i+1 < len(y.n.Content); i += 2 {
		if y.n.Content[i].Value == key {
			y.n.Content[i+1] = v.n
			return nil
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	y.n.Content = append(y.n.Content, keyNode, v.n)
	return nil
}

func (y *yamlNode) Delete(key string) bool {
	if y.n.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(y.n.Content); i += 2 {
		if y.n.Content[i].Value == key {
			y.n.Content = append(y.n.Content[:i], y.n.Content[i+2:]...)
			return true
		}
	}
	return false
}

func (y *yamlNode) SetItem(i int, value Node) error {
	if y.n.Kind != yaml.SequenceNode {
		return ErrUnsupported
	}
	v, ok := value.(*yamlNode)
	if !ok {
		return ErrWrongDocument
	}
	if i < 0 || i >= len(y.n.Content) {
		return ErrUnsupported
	}
	y.n.Content[i] = v.n
	return nil
}

func (y *yamlNode) Append(value Node) error {
	if y.n.Kind != yaml.SequenceNode {
		return ErrUnsupported
	}
	v, ok := value.(*yamlNode)
	if !ok {
		return ErrWrongDocument
	}
	y.n.Content = append(y.n.Content, v.n)
	return nil
}
