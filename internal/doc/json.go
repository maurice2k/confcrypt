package doc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/maurice2k/confcrypt/internal/format"
)

// JSONDocument is a lossless JSON document. Parsing records the byte span of
// every value and the exact bytes between them (whitespace, comments, keys,
// colons), so marshalling copies untouched regions verbatim and only renders
// the nodes that changed. Key order is preserved. New entries are laid out
// in the style of their container (one line, or one entry per line with the
// document's indentation).
//
// JSONC extensions are accepted and preserved: line comments (//), block
// comments (/* */) and a trailing comma before a closing bracket.
type JSONDocument struct {
	src    []byte
	head   []byte // whitespace before the root value
	tail   []byte // whitespace after the root value
	root   *jsonNode
	indent string // detected indentation unit
}

type jsonNode struct {
	doc  *JSONDocument
	kind Kind

	// scalar
	value string
	typ   format.ValueType
	dirty bool // value changed; the original span no longer applies

	// container
	entries       []*jsonEntry
	origEmpty     bool   // container had no entries in the source
	block         bool   // entries are laid out one per line
	blockSet      bool   // block was determined from the source
	trailingComma []byte // bytes before a trailing comma after the last entry (nil if none)

	// source span (src == nil for nodes created after parsing)
	src       []byte
	start     int // offset of the first byte of the value
	end       int // offset just past the last byte
	tailStart int // containers: offset where the whitespace before the closing bracket begins
}

// jsonEntry is one mapping entry or sequence item together with the source
// bytes around it.
type jsonEntry struct {
	key   string
	pre   []byte // bytes between the previous value and the comma (nil for the first entry)
	sep   []byte // bytes between the comma (or opening bracket) and the value, including the key; nil for new entries
	value *jsonNode
}

var jsonNumberRe = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// ParseJSON parses content into a lossless document. Duplicate object keys
// are rejected, since they cannot be matched or encrypted unambiguously.
// Comments and trailing commas (JSONC) are accepted and preserved.
func ParseJSON(content []byte) (*JSONDocument, error) {
	d := &JSONDocument{src: content}
	p := &jsonParser{src: content, doc: d}

	p.skipWS()
	d.head = content[:p.pos]
	root, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	afterRoot := p.pos
	p.skipWS()
	if p.unterminatedComment {
		return nil, p.errorf("unterminated block comment")
	}
	if p.pos != len(content) {
		return nil, p.errorf("unexpected content after JSON value")
	}
	d.tail = content[afterRoot:]
	d.root = root
	d.indent = detectJSONIndent(root, 1)
	if d.indent == "" {
		d.indent = "  "
	}
	return d, nil
}

// Root returns the document's root node.
func (d *JSONDocument) Root() Node {
	return d.root
}

// Indent returns the detected indentation unit used for new entries.
func (d *JSONDocument) Indent() string {
	return d.indent
}

// NewScalar creates a detached scalar node for this document.
func (d *JSONDocument) NewScalar(value string, typ format.ValueType) Node {
	return &jsonNode{doc: d, kind: Scalar, value: value, typ: typ, dirty: true}
}

// NewMapping creates a detached empty mapping node for this document.
func (d *JSONDocument) NewMapping() Node {
	return &jsonNode{doc: d, kind: Mapping, origEmpty: true}
}

// NewSequence creates a detached empty sequence node for this document.
func (d *JSONDocument) NewSequence() Node {
	return &jsonNode{doc: d, kind: Sequence, origEmpty: true}
}

// Marshal renders the document. Regions that were not modified are copied
// from the source byte for byte.
func (d *JSONDocument) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(d.head)
	if err := d.emit(&buf, d.root, 0, true); err != nil {
		return nil, err
	}
	buf.Write(d.tail)
	return buf.Bytes(), nil
}

// detectJSONIndent finds the indentation unit from the first entry that
// starts on its own line. depth is the nesting depth of n's entries.
func detectJSONIndent(n *jsonNode, depth int) string {
	if n.kind == Scalar {
		return ""
	}
	for _, e := range n.entries {
		if e.sep != nil {
			if idx := bytes.LastIndexByte(e.sep, '\n'); idx >= 0 {
				ws := e.sep[idx+1:]
				ws = ws[:len(ws)-len(bytes.TrimLeft(ws, " \t"))]
				if len(ws) >= depth && depth > 0 {
					return string(ws[:len(ws)/depth])
				}
			}
		}
	}
	for _, e := range n.entries {
		if unit := detectJSONIndent(e.value, depth+1); unit != "" {
			return unit
		}
	}
	return ""
}

// ---- parser ----

type jsonParser struct {
	src []byte
	pos int
	doc *JSONDocument

	unterminatedComment bool
}

func (p *jsonParser) errorf(msg string, args ...interface{}) error {
	line, col := 1, 1
	for i := 0; i < p.pos && i < len(p.src); i++ {
		if p.src[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return fmt.Errorf("failed to parse JSON: line %d, column %d: %s", line, col, fmt.Sprintf(msg, args...))
}

// skipWS skips whitespace and JSONC comments. Both end up inside the
// preserved gaps between values, so they survive marshalling untouched.
func (p *jsonParser) skipWS() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		case '/':
			if p.pos+1 >= len(p.src) {
				return
			}
			switch p.src[p.pos+1] {
			case '/':
				end := bytes.IndexByte(p.src[p.pos:], '\n')
				if end < 0 {
					p.pos = len(p.src)
				} else {
					p.pos += end
				}
			case '*':
				end := bytes.Index(p.src[p.pos+2:], []byte("*/"))
				if end < 0 {
					p.pos = len(p.src)
					p.unterminatedComment = true
					return
				}
				p.pos += 2 + end + 2
			default:
				return
			}
		default:
			return
		}
	}
}

func (p *jsonParser) peek() byte {
	if p.pos < len(p.src) {
		return p.src[p.pos]
	}
	return 0
}

func (p *jsonParser) parseValue() (*jsonNode, error) {
	p.skipWS()
	if p.pos >= len(p.src) {
		return nil, p.errorf("unexpected end of input")
	}
	switch c := p.src[p.pos]; {
	case c == '{':
		return p.parseContainer(Mapping)
	case c == '[':
		return p.parseContainer(Sequence)
	case c == '"':
		start := p.pos
		s, err := p.parseString()
		if err != nil {
			return nil, err
		}
		return &jsonNode{doc: p.doc, kind: Scalar, value: s, typ: format.TypeString, src: p.src, start: start, end: p.pos}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	case c == 't' || c == 'f' || c == 'n':
		return p.parseLiteral()
	default:
		return nil, p.errorf("unexpected character %q", c)
	}
}

func (p *jsonParser) parseContainer(kind Kind) (*jsonNode, error) {
	open, close := byte('{'), byte('}')
	if kind == Sequence {
		open, close = '[', ']'
	}
	n := &jsonNode{doc: p.doc, kind: kind, src: p.src, start: p.pos}
	p.pos++ // past the opening bracket
	openEnd := p.pos
	_ = open

	p.skipWS()
	if p.peek() == close {
		n.origEmpty = true
		n.tailStart = openEnd
		p.pos++
		n.end = p.pos
		return n, nil
	}

	seen := make(map[string]bool)
	segStart := openEnd // where this entry's sep begins
	var pre []byte
	for {
		e := &jsonEntry{pre: pre}
		p.skipWS()
		if kind == Mapping {
			if p.peek() != '"' {
				return nil, p.errorf("expected object key")
			}
			key, err := p.parseString()
			if err != nil {
				return nil, err
			}
			if seen[key] {
				return nil, p.errorf("duplicate object key %q", key)
			}
			seen[key] = true
			e.key = key
			p.skipWS()
			if p.peek() != ':' {
				return nil, p.errorf("expected ':' after object key %q", key)
			}
			p.pos++
			p.skipWS()
		}
		e.sep = p.src[segStart:p.pos]
		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		e.value = value
		n.entries = append(n.entries, e)

		afterValue := p.pos
		p.skipWS()
		if p.peek() == ',' {
			pre = p.src[afterValue:p.pos]
			p.pos++
			segStart = p.pos
			p.skipWS()
			if p.peek() != close {
				continue
			}
			// A trailing comma before the closing bracket (JSONC)
			n.trailingComma = pre
			afterValue = segStart
		}
		if p.peek() == close {
			n.tailStart = afterValue
			p.pos++
			n.end = p.pos
			n.block = bytes.IndexByte(n.entries[0].sep, '\n') >= 0
			n.blockSet = true
			return n, nil
		}
		if p.unterminatedComment {
			return nil, p.errorf("unterminated block comment")
		}
		if p.pos >= len(p.src) {
			return nil, p.errorf("unexpected end of input")
		}
		return nil, p.errorf("expected ',' or %q", close)
	}
}

// parseString scans a string token and decodes it. The decoder from
// encoding/json validates escapes and control characters.
func (p *jsonParser) parseString() (string, error) {
	start := p.pos
	i := p.pos + 1
	for {
		if i >= len(p.src) {
			p.pos = i
			return "", p.errorf("unterminated string")
		}
		c := p.src[i]
		if c == '"' {
			break
		}
		if c == '\\' {
			i += 2
			continue
		}
		i++
	}
	raw := p.src[start : i+1]
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", p.errorf("invalid string %s", raw)
	}
	p.pos = i + 1
	return s, nil
}

func (p *jsonParser) parseNumber() (*jsonNode, error) {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' || (c >= '0' && c <= '9') {
			p.pos++
			continue
		}
		break
	}
	raw := string(p.src[start:p.pos])
	if !jsonNumberRe.MatchString(raw) {
		return nil, p.errorf("invalid number %q", raw)
	}
	typ := format.TypeInt
	if strings.ContainsAny(raw, ".eE") {
		typ = format.TypeFloat
	}
	return &jsonNode{doc: p.doc, kind: Scalar, value: raw, typ: typ, src: p.src, start: start, end: p.pos}, nil
}

func (p *jsonParser) parseLiteral() (*jsonNode, error) {
	start := p.pos
	rest := p.src[p.pos:]
	var value string
	var typ format.ValueType
	switch {
	case bytes.HasPrefix(rest, []byte("true")):
		value, typ = "true", format.TypeBool
		p.pos += 4
	case bytes.HasPrefix(rest, []byte("false")):
		value, typ = "false", format.TypeBool
		p.pos += 5
	case bytes.HasPrefix(rest, []byte("null")):
		value, typ = "", format.TypeNull
		p.pos += 4
	default:
		return nil, p.errorf("invalid literal")
	}
	return &jsonNode{doc: p.doc, kind: Scalar, value: value, typ: typ, src: p.src, start: start, end: p.pos}, nil
}

// ---- emitter ----

func (d *JSONDocument) emit(buf *bytes.Buffer, n *jsonNode, depth int, parentBlock bool) error {
	if n.kind == Scalar {
		if n.src != nil && !n.dirty {
			buf.Write(n.src[n.start:n.end])
			return nil
		}
		return writeJSONScalar(buf, n.value, n.typ)
	}

	open, close := byte('{'), byte('}')
	if n.kind == Sequence {
		open, close = '[', ']'
	}
	block := parentBlock
	if n.blockSet {
		block = n.block
	}

	// Entries without source bytes were appended after parsing; they always
	// sit at the end. In a container with a trailing comma (JSONC), the bytes
	// after that comma (typically a comment and the line break) are kept
	// right after the last original entry, so appended entries follow them.
	firstNew := len(n.entries)
	for i, e := range n.entries {
		if e.sep == nil {
			firstNew = i
			break
		}
	}
	var trailingSep []byte
	if n.src != nil && n.trailingComma != nil {
		trailingSep = n.src[n.tailStart : n.end-1]
	}

	buf.WriteByte(open)
	for i, e := range n.entries {
		if i > 0 {
			if i == firstNew && n.trailingComma != nil {
				buf.Write(n.trailingComma)
			} else {
				buf.Write(e.pre)
			}
			buf.WriteByte(',')
		}
		switch {
		case e.sep != nil:
			sep := e.sep
			if i == 0 && e.pre != nil {
				// Promoted to first entry: drop the space that followed the comma
				sep = bytes.TrimLeft(sep, " \t")
			}
			buf.Write(sep)
		default:
			newline := true
			if i == firstNew && i > 0 && len(trailingSep) > 0 {
				kept := bytes.TrimRight(trailingSep, " \t")
				buf.Write(kept)
				newline = !bytes.HasSuffix(kept, []byte("\n"))
			}
			if block {
				if newline {
					buf.WriteByte('\n')
				}
				buf.WriteString(strings.Repeat(d.indent, depth+1))
			} else if i > 0 {
				buf.WriteByte(' ')
			}
			if n.kind == Mapping {
				if err := writeJSONString(buf, e.key); err != nil {
					return err
				}
				buf.WriteString(": ")
			}
		}
		if err := d.emit(buf, e.value, depth+1, block); err != nil {
			return err
		}
	}

	switch {
	case len(n.entries) == 0:
		// Empty container: "{}" / "[]", keeping any comment that was inside
		if n.src != nil && n.origEmpty {
			buf.Write(n.src[n.tailStart : n.end-1])
		}
	case n.src == nil || n.origEmpty:
		var inner []byte
		if n.src != nil {
			inner = n.src[n.tailStart : n.end-1]
		}
		if bytes.IndexByte(inner, '\n') >= 0 {
			buf.Write(inner)
		} else {
			buf.Write(inner)
			if block {
				buf.WriteByte('\n')
				buf.WriteString(strings.Repeat(d.indent, depth))
			}
		}
	case n.trailingComma != nil:
		buf.Write(n.trailingComma)
		buf.WriteByte(',')
		if firstNew == len(n.entries) {
			buf.Write(trailingSep)
		} else if idx := bytes.LastIndexByte(trailingSep, '\n'); idx >= 0 {
			buf.Write(trailingSep[idx:])
		}
	default:
		buf.Write(n.src[n.tailStart : n.end-1])
	}
	buf.WriteByte(close)
	return nil
}

func writeJSONScalar(buf *bytes.Buffer, value string, typ format.ValueType) error {
	switch typ {
	case format.TypeInt, format.TypeFloat:
		if !jsonNumberRe.MatchString(value) {
			return fmt.Errorf("invalid JSON number %q", value)
		}
		buf.WriteString(value)
	case format.TypeBool:
		switch strings.ToLower(value) {
		case "true", "false":
			buf.WriteString(strings.ToLower(value))
		default:
			return fmt.Errorf("invalid JSON boolean %q", value)
		}
	case format.TypeNull:
		buf.WriteString("null")
	default:
		return writeJSONString(buf, value)
	}
	return nil
}

// writeJSONString encodes s as a JSON string without HTML escaping.
func writeJSONString(buf *bytes.Buffer, s string) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	buf.Truncate(buf.Len() - 1) // drop the newline Encode appends
	return nil
}

// ---- Node implementation ----

func (n *jsonNode) Kind() Kind    { return n.kind }
func (n *jsonNode) IsAlias() bool { return false }
func (n *jsonNode) Target() Node  { return n }

func (n *jsonNode) Value() string {
	if n.kind != Scalar {
		return ""
	}
	return n.value
}

func (n *jsonNode) Type() format.ValueType {
	if n.kind != Scalar {
		return format.TypeString
	}
	return n.typ
}

func (n *jsonNode) Tag() string { return "" }

func (n *jsonNode) SetScalar(value string, typ format.ValueType, tag string) {
	n.kind = Scalar
	n.entries = nil
	n.value = value
	n.typ = typ
	n.dirty = true
}

func (n *jsonNode) Len() int {
	if n.kind == Scalar {
		return 0
	}
	return len(n.entries)
}

func (n *jsonNode) Key(i int) string {
	if n.kind != Mapping || i < 0 || i >= len(n.entries) {
		return ""
	}
	return n.entries[i].key
}

func (n *jsonNode) Item(i int) Node {
	if n.kind == Scalar || i < 0 || i >= len(n.entries) {
		return nil
	}
	return n.entries[i].value
}

func (n *jsonNode) Get(key string) (Node, bool) {
	if n.kind != Mapping {
		return nil, false
	}
	for _, e := range n.entries {
		if e.key == key {
			return e.value, true
		}
	}
	return nil, false
}

func (n *jsonNode) sameDoc(value Node) (*jsonNode, error) {
	v, ok := value.(*jsonNode)
	if !ok || v.doc != n.doc {
		return nil, ErrWrongDocument
	}
	return v, nil
}

func (n *jsonNode) Set(key string, value Node) error {
	if n.kind != Mapping {
		return ErrUnsupported
	}
	v, err := n.sameDoc(value)
	if err != nil {
		return err
	}
	for _, e := range n.entries {
		if e.key == key {
			e.value = v
			return nil
		}
	}
	n.entries = append(n.entries, &jsonEntry{key: key, value: v})
	return nil
}

func (n *jsonNode) Delete(key string) bool {
	if n.kind != Mapping {
		return false
	}
	for i, e := range n.entries {
		if e.key == key {
			n.entries = append(n.entries[:i], n.entries[i+1:]...)
			return true
		}
	}
	return false
}

func (n *jsonNode) SetItem(i int, value Node) error {
	if n.kind != Sequence {
		return ErrUnsupported
	}
	v, err := n.sameDoc(value)
	if err != nil {
		return err
	}
	if i < 0 || i >= len(n.entries) {
		return fmt.Errorf("index %d out of range", i)
	}
	n.entries[i].value = v
	return nil
}

func (n *jsonNode) Append(value Node) error {
	if n.kind != Sequence {
		return ErrUnsupported
	}
	v, err := n.sameDoc(value)
	if err != nil {
		return err
	}
	n.entries = append(n.entries, &jsonEntry{value: v})
	return nil
}
