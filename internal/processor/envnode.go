package processor

import (
	"github.com/maurice2k/confcrypt/internal/doc"
	"github.com/maurice2k/confcrypt/internal/format"
)

// envNode adapts an EnvFile to doc.Node: a flat mapping of string scalars.
// Values are the raw text after '=' (including any quotes), which is what
// gets encrypted and restored verbatim.
type envNode struct {
	file *EnvFile
}

// envValue is one key's value, bound to its line in the file.
type envValue struct {
	file *EnvFile
	line int
}

func envDoc(f *EnvFile) doc.Node {
	return &envNode{file: f}
}

func (e *envNode) keyValueLines() []int {
	var idx []int
	for i, line := range e.file.Lines {
		if line.Type == EnvLineKeyValue {
			idx = append(idx, i)
		}
	}
	return idx
}

func (e *envNode) Kind() doc.Kind                             { return doc.Mapping }
func (e *envNode) IsAlias() bool                              { return false }
func (e *envNode) Target() doc.Node                           { return e }
func (e *envNode) Value() string                              { return "" }
func (e *envNode) Type() format.ValueType                     { return format.TypeString }
func (e *envNode) Tag() string                                { return "" }
func (e *envNode) SetScalar(string, format.ValueType, string) {}
func (e *envNode) Len() int                                   { return len(e.keyValueLines()) }
func (e *envNode) SetItem(int, doc.Node) error                { return doc.ErrUnsupported }
func (e *envNode) Append(doc.Node) error                      { return doc.ErrUnsupported }
func (e *envNode) DeleteItem(int) bool                        { return false }

func (e *envNode) Key(i int) string {
	lines := e.keyValueLines()
	if i < 0 || i >= len(lines) {
		return ""
	}
	return e.file.Lines[lines[i]].Key
}

func (e *envNode) Item(i int) doc.Node {
	lines := e.keyValueLines()
	if i < 0 || i >= len(lines) {
		return nil
	}
	return &envValue{file: e.file, line: lines[i]}
}

func (e *envNode) Get(key string) (doc.Node, bool) {
	for i, line := range e.file.Lines {
		if line.Type == EnvLineKeyValue && line.Key == key {
			return &envValue{file: e.file, line: i}, true
		}
	}
	return nil, false
}

// Set updates an existing key or appends a new KEY=value line.
func (e *envNode) Set(key string, value doc.Node) error {
	if value == nil || value.Kind() != doc.Scalar {
		return doc.ErrUnsupported
	}
	if e.file.Set(key, value.Value()) {
		return nil
	}
	// Insert before trailing blank lines so the file keeps its final newline
	insertAt := len(e.file.Lines)
	for insertAt > 0 && e.file.Lines[insertAt-1].Type == EnvLineBlank {
		insertAt--
	}
	newLine := EnvLine{Type: EnvLineKeyValue, Key: key, Value: value.Value()}
	e.file.Lines = append(e.file.Lines[:insertAt], append([]EnvLine{newLine}, e.file.Lines[insertAt:]...)...)
	return nil
}

func (e *envNode) Delete(key string) bool {
	for i, line := range e.file.Lines {
		if line.Type == EnvLineKeyValue && line.Key == key {
			e.file.Lines = append(e.file.Lines[:i], e.file.Lines[i+1:]...)
			return true
		}
	}
	return false
}

func (v *envValue) Kind() doc.Kind         { return doc.Scalar }
func (v *envValue) IsAlias() bool          { return false }
func (v *envValue) Target() doc.Node       { return v }
func (v *envValue) Value() string          { return v.file.Lines[v.line].Value }
func (v *envValue) Type() format.ValueType { return format.TypeString }
func (v *envValue) Tag() string            { return "" }
func (v *envValue) SetScalar(value string, _ format.ValueType, _ string) {
	v.file.Lines[v.line].Value = value
}
func (v *envValue) Len() int                    { return 0 }
func (v *envValue) Key(int) string              { return "" }
func (v *envValue) Item(int) doc.Node           { return nil }
func (v *envValue) Get(string) (doc.Node, bool) { return nil, false }
func (v *envValue) Set(string, doc.Node) error  { return doc.ErrUnsupported }
func (v *envValue) Delete(string) bool          { return false }
func (v *envValue) SetItem(int, doc.Node) error { return doc.ErrUnsupported }
func (v *envValue) Append(doc.Node) error       { return doc.ErrUnsupported }
func (v *envValue) DeleteItem(int) bool         { return false }
