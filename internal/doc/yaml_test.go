package doc

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/maurice2k/confcrypt/internal/format"
)

func parseYAML(t *testing.T, src string) (Node, *yaml.Node) {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(src), &n); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	return FromYAML(&n), &n
}

func marshalYAML(t *testing.T, n *yaml.Node) string {
	t.Helper()
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return buf.String()
}

func TestYAMLAccessorsAndTypes(t *testing.T) {
	root, _ := parseYAML(t, `
s: text
i: 42
f: 1.5
b: true
n: null
ts: !!timestamp 2024-01-02
list: [a, b]
`)
	if root.Kind() != Mapping || root.Len() != 7 || root.Key(0) != "s" {
		t.Fatalf("unexpected root: kind=%v len=%d", root.Kind(), root.Len())
	}
	cases := map[string]struct {
		typ format.ValueType
		tag string
	}{
		"s":  {format.TypeString, ""},
		"i":  {format.TypeInt, ""},
		"f":  {format.TypeFloat, ""},
		"b":  {format.TypeBool, ""},
		"n":  {format.TypeNull, ""},
		"ts": {format.TypeString, "!!timestamp"},
	}
	for key, want := range cases {
		n := get(t, root, key)
		if n.Kind() != Scalar || n.Type() != want.typ || n.Tag() != want.tag {
			t.Errorf("%s: kind=%v type=%q tag=%q, want type=%q tag=%q", key, n.Kind(), n.Type(), n.Tag(), want.typ, want.tag)
		}
	}
	list := get(t, root, "list")
	if list.Kind() != Sequence || list.Len() != 2 || list.Item(1).Value() != "b" {
		t.Errorf("unexpected list: kind=%v len=%d", list.Kind(), list.Len())
	}
	if root.Item(99) != nil || list.Item(-1) != nil || list.Key(0) != "" {
		t.Error("out-of-range access must return zero values")
	}
}

func TestYAMLAliases(t *testing.T) {
	root, _ := parseYAML(t, `
base: &anchor
  password: secret
copy: *anchor
scalar: &s value
ref: *s
`)
	copyNode := get(t, root, "copy")
	if !copyNode.IsAlias() || copyNode.Kind() != Mapping {
		t.Fatalf("copy should be an alias to a mapping, got alias=%v kind=%v", copyNode.IsAlias(), copyNode.Kind())
	}
	if get(t, copyNode.Target(), "password").Value() != "secret" {
		t.Error("alias target not reachable")
	}
	ref := get(t, root, "ref")
	if !ref.IsAlias() || ref.Target().Value() != "value" {
		t.Error("scalar alias not resolved")
	}
	if get(t, root, "base").IsAlias() || get(t, root, "base").Target() == nil {
		t.Error("anchor itself is not an alias")
	}
}

func TestYAMLSetScalarPreservesCommentsAndSetsTag(t *testing.T) {
	root, raw := parseYAML(t, `# head
db:
  password: secret # inline
  port: 5432
`)
	get(t, root, "db", "password").SetScalar("ENC[x]", format.TypeString, "")
	get(t, root, "db", "port").SetScalar("1", format.TypeInt, "")
	out := marshalYAML(t, raw)
	want := "# head\ndb:\n  password: ENC[x] # inline\n  port: 1\n"
	if out != want {
		t.Errorf("unexpected output:\n got: %q\nwant: %q", out, want)
	}
	if YAML(get(t, root, "db", "port")).Tag != "!!int" {
		t.Error("expected !!int tag after SetScalar with TypeInt")
	}

	get(t, root, "db", "port").SetScalar("2024-01-02", format.TypeString, "!!timestamp")
	if YAML(get(t, root, "db", "port")).Tag != "!!timestamp" {
		t.Error("explicit tag must win over type")
	}
}

func TestYAMLMutators(t *testing.T) {
	root, raw := parseYAML(t, "a: 1\nlist:\n  - x\n")
	if err := root.Set("b", NewYAMLScalar("2", format.TypeInt, "")); err != nil {
		t.Fatal(err)
	}
	if err := root.Set("a", NewYAMLScalar("replaced", format.TypeString, "")); err != nil {
		t.Fatal(err)
	}
	list := get(t, root, "list")
	if err := list.Append(NewYAMLScalar("y", format.TypeString, "")); err != nil {
		t.Fatal(err)
	}
	if err := list.SetItem(0, NewYAMLScalar("z", format.TypeString, "")); err != nil {
		t.Fatal(err)
	}
	m := NewYAMLMapping()
	_ = m.Set("k", NewYAMLScalar("v", format.TypeString, ""))
	s := NewYAMLSequence()
	_ = s.Append(NewYAMLScalar("1", format.TypeInt, ""))
	_ = m.Set("s", s)
	_ = root.Set("m", m)

	out := marshalYAML(t, raw)
	want := "a: replaced\nlist:\n  - z\n  - y\nb: 2\nm:\n  k: v\n  s:\n    - 1\n"
	if out != want {
		t.Errorf("unexpected output:\n got: %q\nwant: %q", out, want)
	}

	if !root.Delete("b") || root.Delete("b") {
		t.Error("Delete must remove once and report absence afterwards")
	}
	if strings.Contains(marshalYAML(t, raw), "b: 2") {
		t.Error("deleted key still present")
	}

	if err := list.Set("k", NewYAMLScalar("v", format.TypeString, "")); err != ErrUnsupported {
		t.Errorf("Set on sequence: got %v", err)
	}
	if err := root.Append(NewYAMLScalar("v", format.TypeString, "")); err != ErrUnsupported {
		t.Errorf("Append on mapping: got %v", err)
	}
	if err := list.SetItem(9, NewYAMLScalar("v", format.TypeString, "")); err == nil {
		t.Error("SetItem out of range must fail")
	}
	d := mustParseJSON(t, `{}`)
	if err := root.Set("j", d.NewScalar("v", format.TypeString)); err != ErrWrongDocument {
		t.Errorf("Set with JSON node: got %v, want ErrWrongDocument", err)
	}
}

func TestYAMLEmptyDocument(t *testing.T) {
	var n yaml.Node
	if FromYAML(&n) != nil || FromYAML(nil) != nil {
		t.Error("empty document must yield nil")
	}
	if YAML(mustParseJSON(t, `{}`).Root()) != nil {
		t.Error("YAML() on a JSON node must be nil")
	}
}
