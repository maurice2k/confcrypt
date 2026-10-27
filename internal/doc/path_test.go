package doc

import (
	"strings"
	"testing"
)

func TestParsePathAndString(t *testing.T) {
	cases := map[string]string{
		"a":                 "a",
		"a.b.c":             "a.b.c",
		"a[0]":              "a[0]",
		"a[0][1].b":         "a[0][1].b",
		"[2].x":             "[2].x",
		`"a.b".c`:           `"a.b".c`,
		`"with \"quote\""`:  `"with \"quote\""`,
		`"back\\slash"`:     `"back\\slash"`,
		`a."plain"`:         "a.plain",
		"list[+]":           "list[+]",
		"snake_case-key.v2": "snake_case-key.v2",
		"key with spaces":   "key with spaces",
	}
	for in, want := range cases {
		p, err := ParsePath(in)
		if err != nil {
			t.Errorf("ParsePath(%q): %v", in, err)
			continue
		}
		if got := p.String(); got != want {
			t.Errorf("ParsePath(%q).String() = %q, want %q", in, got, want)
		}
		// String output parses back to the same path
		p2, err := ParsePath(p.String())
		if err != nil || p2.String() != p.String() {
			t.Errorf("round trip of %q failed: %v", in, err)
		}
	}

	p, _ := ParsePath(`db.hosts[1]."weird.key"[+]`)
	want := Path{{Key: "db"}, {Key: "hosts"}, {Index: 1, IsIndex: true}, {Key: "weird.key"}, {Append: true, IsIndex: true}}
	if len(p) != len(want) {
		t.Fatalf("got %d segments, want %d", len(p), len(want))
	}
	for i := range want {
		if p[i] != want[i] {
			t.Errorf("segment %d: got %+v, want %+v", i, p[i], want[i])
		}
	}
}

func TestParsePathErrors(t *testing.T) {
	for _, in := range []string{
		"", "   ", "..", "a.", ".a", "a..b", "a[", "a[x]", "a[-1]", "a[+1]", `"unterminated`, `"dangling\`,
		"a]b", `a"b`, "a[0]b", "a[0]]",
	} {
		if _, err := ParsePath(in); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestResolve(t *testing.T) {
	d := mustParseJSON(t, `{"db": {"hosts": [{"name": "h1", "port": 1}, "plain"], "a.b": {"c": true}}, "top": null}`)
	root := d.Root()

	for in, want := range map[string]string{
		"db.hosts[0].name": "h1",
		"db.hosts[0].port": "1",
		"db.hosts[1]":      "plain",
		`db."a.b".c`:       "true",
		"top":              "",
	} {
		p, _ := ParsePath(in)
		n, err := Resolve(root, p)
		if err != nil {
			t.Errorf("Resolve(%q): %v", in, err)
			continue
		}
		if n.Kind() != Scalar || n.Value() != want {
			t.Errorf("Resolve(%q) = kind %v value %q, want %q", in, n.Kind(), n.Value(), want)
		}
	}

	n, err := Resolve(root, nil)
	if err != nil || n != root {
		t.Errorf("empty path must resolve to root")
	}
	dot, err := ParsePath(".")
	if err != nil || len(dot) != 0 || dot.String() != "." {
		t.Errorf("\".\" must parse to the empty path, got %v %v", dot, err)
	}
	if n, err := Resolve(root, dot); err != nil || n != root {
		t.Errorf("\".\" must resolve to root")
	}

	for in, wantErr := range map[string]string{
		"missing":            `key "missing" not found in the document root`,
		"db.nope":            `key "nope" not found in db`,
		"db.hosts[5]":        "db.hosts has 2 item(s), index 5 is out of range",
		"db[0]":              "db is not a list",
		"db.hosts[1].x":      "db.hosts[1] is not a mapping",
		"top.x":              "top is not a mapping",
		"db.hosts[+]":        "[+] can only be used when setting",
		"db.hosts[0].name.x": "db.hosts[0].name is not a mapping",
	} {
		p, err := ParsePath(in)
		if err != nil {
			t.Fatalf("ParsePath(%q): %v", in, err)
		}
		_, err = Resolve(root, p)
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("Resolve(%q): got %v, want error containing %q", in, err, wantErr)
		}
	}
}

func TestResolveFollowsYAMLAliases(t *testing.T) {
	root, _ := parseYAML(t, "base: &b\n  password: secret\ncopy: *b\nlist: &l [x, y]\nref: *l\n")
	p, _ := ParsePath("copy.password")
	n, err := Resolve(root, p)
	if err != nil || n.Value() != "secret" {
		t.Errorf("alias mapping: %v %q", err, n)
	}
	p, _ = ParsePath("ref[1]")
	n, err = Resolve(root, p)
	if err != nil || n.Value() != "y" {
		t.Errorf("alias list: %v", err)
	}
}

func TestRenderJSON(t *testing.T) {
	d := mustParseJSON(t, "{\"z\": 1, \"a\": {\"l\": [true, null, 1.50, \"<s>\"], \"e\": {}, \"f\": []}}")
	out, err := RenderJSON(d.Root())
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"z\": 1,\n  \"a\": {\n    \"l\": [\n      true,\n      null,\n      1.50,\n      \"<s>\"\n    ],\n    \"e\": {},\n    \"f\": []\n  }\n}"
	if string(out) != want {
		t.Errorf("unexpected JSON:\n got: %q\nwant: %q", out, want)
	}

	// YAML nodes render too; non-JSON numbers fall back to strings
	root, _ := parseYAML(t, "hex: 0x1f\nn: 42\ns: yes\nb: true\nnull_value:\n")
	out, err = RenderJSON(root)
	if err != nil {
		t.Fatal(err)
	}
	want = "{\n  \"hex\": \"0x1f\",\n  \"n\": 42,\n  \"s\": \"yes\",\n  \"b\": true,\n  \"null_value\": null\n}"
	if string(out) != want {
		t.Errorf("unexpected JSON from YAML:\n got: %q\nwant: %q", out, want)
	}

	scalar, _ := ParsePath("n")
	sn, _ := Resolve(root, scalar)
	if out, _ := RenderJSON(sn); string(out) != "42" {
		t.Errorf("scalar: got %q", out)
	}
}

func TestRenderYAML(t *testing.T) {
	root, _ := parseYAML(t, "# top\ndb:\n  host: localhost # inline\n  port: 5432\n")
	p, _ := ParsePath("db")
	n, _ := Resolve(root, p)
	out, err := RenderYAML(n)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "host: localhost # inline\nport: 5432\n" {
		t.Errorf("unexpected YAML:\n%q", out)
	}

	d := mustParseJSON(t, `{"a": [1, "x", null, true, 1.5], "b": {}}`)
	out, err = RenderYAML(d.Root())
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "a:\n  - 1\n  - x\n  - null\n  - true\n  - 1.5\nb: {}\n" {
		t.Errorf("unexpected YAML from JSON:\n%q", out)
	}
	if out, _ := RenderYAML(nil); string(out) != "null\n" {
		t.Errorf("nil renders null, got %q", out)
	}
}
