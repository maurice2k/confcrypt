package doc

import (
	"strings"
	"testing"

	"github.com/maurice2k/confcrypt/internal/format"
)

func mustParseJSON(t *testing.T, src string) *JSONDocument {
	t.Helper()
	d, err := ParseJSON([]byte(src))
	if err != nil {
		t.Fatalf("ParseJSON(%q): %v", src, err)
	}
	return d
}

func mustMarshal(t *testing.T, d *JSONDocument) string {
	t.Helper()
	out, err := d.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(out)
}

// get walks a dotted path of mapping keys and returns the node.
func get(t *testing.T, n Node, path ...string) Node {
	t.Helper()
	for _, key := range path {
		child, ok := n.Get(key)
		if !ok {
			t.Fatalf("key %q not found", key)
		}
		n = child
	}
	return n
}

var losslessCorpus = []string{
	`{}`,
	`[]`,
	`{"a":1}`,
	`{ "a" : 1 , "b" : [ 1 , 2 ] }`,
	"{\n  \"a\": 1,\n  \"b\": {\n    \"c\": [1, 2, 3],\n    \"d\": {}\n  }\n}\n",
	"{\n\t\"tabs\": true,\n\t\"nested\": {\n\t\t\"x\": null\n\t}\n}",
	"{\r\n  \"crlf\": \"yes\"\r\n}\r\n",
	"\n\n  {\"leading\": \"whitespace\"}  \n\n",
	`{"esc": "a\"b\\c\/dé\n<tag>&"}`,
	`{"num": [0, -1, 1.50, 1e10, 2E-3, 12345678901234567890, 0.0]}`,
	`[{"a": 1}, {"b": 2}, [[[]]], "s", true, false, null]`,
	`"just a string"`,
	`42`,
	"{\n    \"four\": {\n        \"spaces\": 1\n    }\n}",
	"{\"a\":1,\n\n\n\"blank lines\":2}",
	"{\"unicode\": \"héllo 🙂\", \"key with spaces\": 1}",
	"{\"a\": {\"b\": {\"c\": {\"d\": {\"e\": \"deep\"}}}}}",
}

var jsoncCorpus = []string{
	"// settings\n{\n  // line comment\n  \"a\": 1, // trailing comment\n  /* block */ \"b\": /* between */ 2,\n  \"list\": [\n    1, // one\n    2,\n  ],\n  \"c\": 3,\n  // last\n}\n// end\n",
	"{\"a\": 1,}",
	"[1, 2, /* c */]",
	"{\n  \"url\": \"http://example.com/not-a-comment\",\n  \"s\": \"/* not a comment */ // nor this\"\n}",
	"/* only */ 42 /* value */",
	"{/* in empty */}",
	"{\n  \"a\": {\n    // nested comment only\n  }\n}",
}

func TestJSONCRoundTripIsLossless(t *testing.T) {
	for _, src := range jsoncCorpus {
		d := mustParseJSON(t, src)
		if out := mustMarshal(t, d); out != src {
			t.Errorf("round trip changed content:\n got: %q\nwant: %q", out, src)
		}
	}
}

func TestJSONCReplaceKeepsComments(t *testing.T) {
	src := "{\n  // db settings\n  \"password\": \"s3cret\", // keep me\n  \"port\": 5432, /* keep */\n}\n"
	d := mustParseJSON(t, src)
	get(t, d.Root(), "password").SetScalar("ENC[x]", format.TypeString, "")
	want := strings.Replace(src, `"s3cret"`, `"ENC[x]"`, 1)
	if out := mustMarshal(t, d); out != want {
		t.Errorf("unexpected output:\n got: %q\nwant: %q", out, want)
	}
	if get(t, d.Root(), "port").Value() != "5432" {
		t.Error("value after comment not parsed")
	}
}

func TestJSONCStructuralEditsKeepTrailingComma(t *testing.T) {
	d := mustParseJSON(t, "{\n  \"a\": 1,\n  \"b\": 2, // b\n}\n")
	_ = d.Root().Set("c", d.NewScalar("3", format.TypeInt))
	if out, want := mustMarshal(t, d), "{\n  \"a\": 1,\n  \"b\": 2, // b\n  \"c\": 3,\n}\n"; out != want {
		t.Errorf("append with trailing comma:\n got: %q\nwant: %q", out, want)
	}

	d = mustParseJSON(t, "[1, 2,]")
	_ = d.Root().Append(d.NewScalar("3", format.TypeInt))
	if out, want := mustMarshal(t, d), "[1, 2, 3,]"; out != want {
		t.Errorf("append flow with trailing comma:\n got: %q\nwant: %q", out, want)
	}

	// Appending into an empty container keeps the comment that was inside
	d = mustParseJSON(t, "{\n  \"a\": {\n    // nested comment only\n  }\n}")
	_ = get(t, d.Root(), "a").Set("k", d.NewScalar("v", format.TypeString))
	if out, want := mustMarshal(t, d), "{\n  \"a\": {\n    \"k\": \"v\"\n    // nested comment only\n  }\n}"; out != want {
		t.Errorf("append into commented empty:\n got: %q\nwant: %q", out, want)
	}

	// Deleting an entry drops the comment that was attached to it
	d = mustParseJSON(t, "{\n  // about a\n  \"a\": 1,\n  \"b\": 2,\n}\n")
	d.Root().Delete("a")
	if out, want := mustMarshal(t, d), "{\n  \"b\": 2,\n}\n"; out != want {
		t.Errorf("delete with comment:\n got: %q\nwant: %q", out, want)
	}
}

func TestJSONCParseErrors(t *testing.T) {
	for _, src := range []string{
		"{\"a\": 1 /* unterminated",
		"/* unterminated",
		"{\"a\": 1,,}",
		"{,}",
		"[,]",
		"{\"a\": 1} // ok\n junk",
		"{\"a\": 1 / 2}",
	} {
		if _, err := ParseJSON([]byte(src)); err == nil {
			t.Errorf("expected parse error for %q", src)
		}
	}
}

func TestJSONRoundTripIsLossless(t *testing.T) {
	for _, src := range losslessCorpus {
		d := mustParseJSON(t, src)
		if out := mustMarshal(t, d); out != src {
			t.Errorf("round trip changed content:\n got: %q\nwant: %q", out, src)
		}
	}
}

func TestJSONScalarReplacementOnlyTouchesThatToken(t *testing.T) {
	src := "{\n  \"db\": {\n    \"host\": \"localhost\",\n    \"password\": \"s3cret\" ,\n    \"port\": 5432\n  },\n  \"list\": [ \"a\", \"b\" ]\n}\n"
	d := mustParseJSON(t, src)

	get(t, d.Root(), "db", "password").SetScalar("ENC[x]", format.TypeString, "")
	want := strings.Replace(src, `"s3cret"`, `"ENC[x]"`, 1)
	if out := mustMarshal(t, d); out != want {
		t.Errorf("unexpected output:\n got: %q\nwant: %q", out, want)
	}

	// Replacing a number with a string and a list item keeps everything else
	get(t, d.Root(), "db", "port").SetScalar("ENC[y]", format.TypeString, "")
	get(t, d.Root(), "list").Item(1).SetScalar("ENC[z]", format.TypeString, "")
	want = strings.Replace(want, `5432`, `"ENC[y]"`, 1)
	want = strings.Replace(want, `"b"`, `"ENC[z]"`, 1)
	if out := mustMarshal(t, d); out != want {
		t.Errorf("unexpected output:\n got: %q\nwant: %q", out, want)
	}
}

func TestJSONScalarTypesAndValues(t *testing.T) {
	d := mustParseJSON(t, `{"s": "x", "i": 12345678901234567890, "f": 1.50, "e": 1e3, "b": true, "n": null}`)
	root := d.Root()
	cases := map[string]struct {
		value string
		typ   format.ValueType
	}{
		"s": {"x", format.TypeString},
		"i": {"12345678901234567890", format.TypeInt},
		"f": {"1.50", format.TypeFloat},
		"e": {"1e3", format.TypeFloat},
		"b": {"true", format.TypeBool},
		"n": {"", format.TypeNull},
	}
	for key, want := range cases {
		n := get(t, root, key)
		if n.Kind() != Scalar || n.Value() != want.value || n.Type() != want.typ {
			t.Errorf("%s: got kind=%v value=%q type=%q, want value=%q type=%q", key, n.Kind(), n.Value(), n.Type(), want.value, want.typ)
		}
	}
}

func TestJSONEmitTypedScalars(t *testing.T) {
	src := `{"a": "x", "b": "x", "c": "x", "d": "x", "e": "x"}`
	d := mustParseJSON(t, src)
	root := d.Root()
	get(t, root, "a").SetScalar("42", format.TypeInt, "")
	get(t, root, "b").SetScalar("1.50", format.TypeFloat, "")
	get(t, root, "c").SetScalar("True", format.TypeBool, "")
	get(t, root, "d").SetScalar("", format.TypeNull, "")
	get(t, root, "e").SetScalar("<a href=\"x\">é & ü</a>\n", format.TypeString, "")
	want := `{"a": 42, "b": 1.50, "c": true, "d": null, "e": "<a href=\"x\">é & ü</a>\n"}`
	if out := mustMarshal(t, d); out != want {
		t.Errorf("unexpected output:\n got: %s\nwant: %s", out, want)
	}
}

func TestJSONEmitRejectsInvalidTypedValues(t *testing.T) {
	for _, tc := range []struct {
		value string
		typ   format.ValueType
	}{
		{"12abc", format.TypeInt},
		{"1.", format.TypeFloat},
		{"yes", format.TypeBool},
		{"", format.TypeInt},
	} {
		d := mustParseJSON(t, `{"a": 1}`)
		get(t, d.Root(), "a").SetScalar(tc.value, tc.typ, "")
		if _, err := d.Marshal(); err == nil {
			t.Errorf("expected error for %q as %s", tc.value, tc.typ)
		}
	}
}

func TestJSONParseErrors(t *testing.T) {
	for _, src := range []string{
		``,
		`   `,
		`{"a": 1, "a": 2}`,
		`{"a": 1} x`,
		`{"a": 01}`,
		`{"a": 1.}`,
		`{"a": "unterminated}`,
		`{"a": "bad \x escape"}`,
		`{"a": tru}`,
		`{"a" 1}`,
		`[1 2]`,
		`{"a": 1`,
		`{a: 1}`,
		"{\"a\": \"tab\tinside\"}",
	} {
		if _, err := ParseJSON([]byte(src)); err == nil {
			t.Errorf("expected parse error for %q", src)
		}
	}
	_, err := ParseJSON([]byte("{\n  \"a\": 1,\n  \"a\": 2\n}"))
	if err == nil || !strings.Contains(err.Error(), "line 3") || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate-key error with position, got %v", err)
	}
}

func TestJSONSetNewKeyBlockStyle(t *testing.T) {
	d := mustParseJSON(t, "{\n  \"a\": 1,\n  \"nested\": {\n    \"b\": 2\n  }\n}\n")
	root := d.Root()
	if err := root.Set("c", d.NewScalar("new", format.TypeString)); err != nil {
		t.Fatal(err)
	}
	if err := get(t, root, "nested").Set("d", d.NewScalar("3", format.TypeInt)); err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"a\": 1,\n  \"nested\": {\n    \"b\": 2,\n    \"d\": 3\n  },\n  \"c\": \"new\"\n}\n"
	if out := mustMarshal(t, d); out != want {
		t.Errorf("unexpected output:\n got: %q\nwant: %q", out, want)
	}
}

func TestJSONSetNewKeyFlowStyle(t *testing.T) {
	d := mustParseJSON(t, `{"a": 1, "l": [1, 2]}`)
	root := d.Root()
	if err := root.Set("b", d.NewScalar("x", format.TypeString)); err != nil {
		t.Fatal(err)
	}
	if err := get(t, root, "l").Append(d.NewScalar("3", format.TypeInt)); err != nil {
		t.Fatal(err)
	}
	want := `{"a": 1, "l": [1, 2, 3], "b": "x"}`
	if out := mustMarshal(t, d); out != want {
		t.Errorf("unexpected output:\n got: %s\nwant: %s", out, want)
	}
}

func TestJSONSetIntoEmptyContainers(t *testing.T) {
	d := mustParseJSON(t, "{\n  \"m\": {},\n  \"l\": []\n}")
	root := d.Root()
	if err := get(t, root, "m").Set("k", d.NewScalar("v", format.TypeString)); err != nil {
		t.Fatal(err)
	}
	if err := get(t, root, "l").Append(d.NewScalar("1", format.TypeInt)); err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"m\": {\n    \"k\": \"v\"\n  },\n  \"l\": [\n    1\n  ]\n}"
	if out := mustMarshal(t, d); out != want {
		t.Errorf("unexpected output:\n got: %q\nwant: %q", out, want)
	}

	// Empty containers inside a flow-style parent stay on one line
	d = mustParseJSON(t, `{"m": {}, "l": []}`)
	root = d.Root()
	_ = get(t, root, "m").Set("k", d.NewScalar("v", format.TypeString))
	_ = get(t, root, "l").Append(d.NewScalar("1", format.TypeInt))
	want = `{"m": {"k": "v"}, "l": [1]}`
	if out := mustMarshal(t, d); out != want {
		t.Errorf("unexpected output:\n got: %s\nwant: %s", out, want)
	}
}

func TestJSONSetNestedNewContainer(t *testing.T) {
	d := mustParseJSON(t, "{\n  \"a\": 1\n}\n")
	m := d.NewMapping()
	_ = m.Set("x", d.NewScalar("1", format.TypeInt))
	s := d.NewSequence()
	_ = s.Append(d.NewScalar("y", format.TypeString))
	_ = m.Set("list", s)
	if err := d.Root().Set("new", m); err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"a\": 1,\n  \"new\": {\n    \"x\": 1,\n    \"list\": [\n      \"y\"\n    ]\n  }\n}\n"
	if out := mustMarshal(t, d); out != want {
		t.Errorf("unexpected output:\n got: %q\nwant: %q", out, want)
	}
}

func TestJSONDelete(t *testing.T) {
	src := "{\n  \"a\": 1,\n  \"b\": 2,\n  \"c\": 3\n}\n"

	d := mustParseJSON(t, src)
	if !d.Root().Delete("a") {
		t.Fatal("expected a to be deleted")
	}
	if out, want := mustMarshal(t, d), "{\n  \"b\": 2,\n  \"c\": 3\n}\n"; out != want {
		t.Errorf("delete first:\n got: %q\nwant: %q", out, want)
	}

	d = mustParseJSON(t, src)
	d.Root().Delete("b")
	if out, want := mustMarshal(t, d), "{\n  \"a\": 1,\n  \"c\": 3\n}\n"; out != want {
		t.Errorf("delete middle:\n got: %q\nwant: %q", out, want)
	}

	d = mustParseJSON(t, src)
	d.Root().Delete("c")
	if out, want := mustMarshal(t, d), "{\n  \"a\": 1,\n  \"b\": 2\n}\n"; out != want {
		t.Errorf("delete last:\n got: %q\nwant: %q", out, want)
	}

	d = mustParseJSON(t, src)
	d.Root().Delete("a")
	d.Root().Delete("b")
	d.Root().Delete("c")
	if out, want := mustMarshal(t, d), "{}\n"; out != want {
		t.Errorf("delete all:\n got: %q\nwant: %q", out, want)
	}
	if d.Root().Delete("missing") {
		t.Error("deleting a missing key must return false")
	}

	d = mustParseJSON(t, `{"a": 1, "b": 2}`)
	d.Root().Delete("a")
	if out, want := mustMarshal(t, d), `{"b": 2}`; out != want {
		t.Errorf("delete first (flow):\n got: %s\nwant: %s", out, want)
	}
}

func TestJSONDetectsIndentation(t *testing.T) {
	for src, want := range map[string]string{
		"{\n    \"a\": 1\n}":               "    ",
		"{\n\t\"a\": 1\n}":                 "\t",
		"{\"a\": {\n      \"b\": 1\n   }}": "   ",
		`{"a": 1}`:                         "  ",
	} {
		if got := mustParseJSON(t, src).Indent(); got != want {
			t.Errorf("%q: indent %q, want %q", src, got, want)
		}
	}
}

func TestJSONNodeAccessors(t *testing.T) {
	d := mustParseJSON(t, `{"a": [1, {"b": 2}], "c": "x"}`)
	root := d.Root()
	if root.Kind() != Mapping || root.Len() != 2 || root.Key(0) != "a" || root.Key(1) != "c" {
		t.Fatalf("unexpected root: kind=%v len=%d keys=%q,%q", root.Kind(), root.Len(), root.Key(0), root.Key(1))
	}
	list := root.Item(0)
	if list.Kind() != Sequence || list.Len() != 2 || list.Key(0) != "" {
		t.Fatalf("unexpected list: kind=%v len=%d", list.Kind(), list.Len())
	}
	if list.Item(1).Kind() != Mapping || get(t, list.Item(1), "b").Value() != "2" {
		t.Error("nested mapping in list not reachable")
	}
	if list.Item(5) != nil || root.Item(-1) != nil || root.Key(9) != "" {
		t.Error("out-of-range access must return zero values")
	}
	if root.IsAlias() || root.Target() != root || root.Tag() != "" {
		t.Error("JSON nodes have no aliases or tags")
	}
	if _, ok := root.Get("missing"); ok {
		t.Error("Get on missing key must return false")
	}
	if err := list.Set("k", d.NewScalar("v", format.TypeString)); err != ErrUnsupported {
		t.Errorf("Set on sequence: got %v, want ErrUnsupported", err)
	}
	if err := root.Append(d.NewScalar("v", format.TypeString)); err != ErrUnsupported {
		t.Errorf("Append on mapping: got %v, want ErrUnsupported", err)
	}
	if err := list.SetItem(7, d.NewScalar("v", format.TypeString)); err == nil {
		t.Error("SetItem out of range must fail")
	}
	other := mustParseJSON(t, `{}`)
	if err := root.Set("k", other.NewScalar("v", format.TypeString)); err != ErrWrongDocument {
		t.Errorf("Set with node from other document: got %v, want ErrWrongDocument", err)
	}
	if err := root.Set("k", NewYAMLScalar("v", format.TypeString, "")); err != ErrWrongDocument {
		t.Errorf("Set with YAML node: got %v, want ErrWrongDocument", err)
	}
}

func TestJSONSetItemReplacesListValue(t *testing.T) {
	d := mustParseJSON(t, "[\n  1,\n  2\n]")
	if err := d.Root().SetItem(0, d.NewScalar("x", format.TypeString)); err != nil {
		t.Fatal(err)
	}
	if out, want := mustMarshal(t, d), "[\n  \"x\",\n  2\n]"; out != want {
		t.Errorf("unexpected output:\n got: %q\nwant: %q", out, want)
	}
}
