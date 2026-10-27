// Package doc provides a format-independent view of structured config
// documents (YAML, JSON, env) so that encryption, matching and lookup logic
// is written once. Each format keeps its own representation underneath
// (comments, key order, original bytes) and only exposes it through Node.
package doc

import (
	"errors"

	"github.com/maurice2k/confcrypt/internal/format"
)

// Kind is the structural kind of a node.
type Kind int

const (
	Scalar Kind = iota
	Mapping
	Sequence
)

func (k Kind) String() string {
	switch k {
	case Scalar:
		return "scalar"
	case Mapping:
		return "mapping"
	case Sequence:
		return "sequence"
	default:
		return "unknown"
	}
}

// ErrUnsupported is returned by mutators a document format cannot perform.
var ErrUnsupported = errors.New("operation not supported by this document format")

// ErrWrongDocument is returned when a node from a different document (or
// format) is inserted into a document.
var ErrWrongDocument = errors.New("node belongs to a different document")

// Node is one node of a structured document. Accessors for the wrong kind
// return zero values; mutators for the wrong kind return ErrUnsupported.
//
// Mappings are ordered: Len, Key and Item iterate entries in document order.
// Sequences use Len and Item. Scalars expose their textual value plus a
// portable type and, for formats that need it, a format-specific tag.
type Node interface {
	Kind() Kind

	// IsAlias reports whether the node is a reference to another node
	// (YAML aliases). Target returns the referenced node for aliases and the
	// node itself otherwise.
	IsAlias() bool
	Target() Node

	// Scalar accessors. Value is the textual value: the decoded string, the
	// number literal as written, "true"/"false", or "" for null.
	Value() string
	Type() format.ValueType
	// Tag is a format-specific type tag that Type cannot represent (for
	// example a custom YAML tag), or "" if there is none.
	Tag() string
	// SetScalar replaces the scalar's value. A non-empty tag takes precedence
	// over typ for formats that support tags.
	SetScalar(value string, typ format.ValueType, tag string)

	// Container accessors. Key is only meaningful for mappings.
	Len() int
	Key(i int) string
	Item(i int) Node

	// Mapping mutators. Set replaces the value of an existing key or appends
	// a new entry.
	Get(key string) (Node, bool)
	Set(key string, value Node) error
	Delete(key string) bool

	// Sequence mutators.
	SetItem(i int, value Node) error
	Append(value Node) error
	DeleteItem(i int) bool
}
