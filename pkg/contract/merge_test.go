package contract

import (
	"os"
	"strings"
	"testing"
)

// Issue #152 item 2: a key written after a merge key overrides the merged one
// on a struct field as on a map, in Parse and in DecodeYAML (the loader's
// peek) alike.
func TestMergeOverridesOnStructs(t *testing.T) {
	data, err := os.ReadFile("testdata/good/tags-and-merge-overrides.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if c.Metadata.ID != "demo-merge-override" || c.Metadata.Summary != "merged" || c.Metadata.Severity != "high" {
		t.Errorf("metadata = %+v", c.Metadata)
	}
	v := c.States[StateVulnerable].Verify
	if h := v[0].HTTP; h == nil || h.Path != "/" || h.Status == nil || *h.Status != 404 {
		t.Errorf("verify[0].http = %+v, want path / and status 404", h)
	}
	if p := c.States[StatePatched].Verify[0].TCP; p == nil || p.Port != 80 || p.Timeout != 10 {
		t.Errorf("patched tcp = %+v, want port 80 and timeout 10", p)
	}
	if hc := c.Service.Healthcheck.HTTP; hc == nil || hc.Status != 200 {
		t.Errorf("the anchored mapping changed: %+v", hc)
	}
	if env := c.States[StatePatched].Environment; env["MODE"] != "patched" || env["OTHER"] != "y" {
		t.Errorf("patched environment = %v", env)
	}
	var peek struct {
		Metadata struct {
			ID       string `yaml:"id"`
			Severity string `yaml:"severity"`
		} `yaml:"metadata"`
	}
	if err := DecodeYAML(data, &peek); err != nil {
		t.Fatal(err)
	}
	if peek.Metadata.ID != "demo-merge-override" || peek.Metadata.Severity != "high" {
		t.Errorf("DecodeYAML read %+v", peek.Metadata)
	}
}

// The forms on which YAML and goccy disagree about which value wins are
// rejected, by Parse and by DecodeYAML.
func TestMergeAmbiguityRejected(t *testing.T) {
	for doc, want := range map[string]string{
		"r: &r {a: 1, b: 2}\nx: {b: 3, <<: *r}\n":                 `key "b" overrides a key merged by a later <<`,
		"r: &r {a: 1}\ns: &s {a: 2}\nx: {<<: [*r, *s]}\n":         `key "a" is merged from more than one mapping`,
		"x: {<<: {a: 1, a: 2}}\n":                                 `mapping key "a" already defined`, // the parser reports it first
		"r: &r {a: 1}\ns: &s {a: 2}\nx: {<<: [*r, *s], a: 3}\n":   "",
		"r: &r {a: 1}\nx: {<<: [*r, *r]}\n":                       "",
		"r: &r {a: 1, b: 2}\nx: {<<: *r, b: 3}\n":                 "",
		"r: &r {a: 1}\ns: &s {<<: *r, b: 2}\nx: {<<: *s, a: 3}\n": "",
		"r: &r {a: 1}\ns: &s {<<: *r, b: 2}\nx: {<<: [*s, *r]}\n": "",
		"r: &r {a: 1}\ns: &s {<<: *r, a: 2}\nx: {<<: [*s, *r]}\n": `key "a" is merged from more than one mapping`,
	} {
		var v map[string]map[string]int
		err := DecodeYAML([]byte(doc), &v)
		switch {
		case want == "" && err != nil:
			t.Errorf("%q: %v", doc, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%q: got %v, want %q", doc, err, want)
		}
	}
	var v map[string]map[string]int
	if err := DecodeYAML([]byte("r: &r {a: 1}\ns: &s {<<: *r, b: 2}\nx: {<<: [*s, *r]}\n"), &v); err != nil || v["x"]["a"] != 1 || v["x"]["b"] != 2 {
		t.Errorf("nested merge: %v %v", v, err)
	}
}

// Issue #152 item 1: a core tag gives a scalar its type, for the type check
// and the decoder alike.
func TestCoreTagsDecode(t *testing.T) {
	data, err := os.ReadFile("testdata/good/tags-and-merge-overrides.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if c.Service.Ports[0].Container != 80 {
		t.Errorf("container = %d", c.Service.Ports[0].Container)
	}
	if env := c.Service.Environment; env["A"] != "1" || env["B"] != "true" || env["C"] != "1.5" {
		t.Errorf("environment = %v", env)
	}
	// !!str keeps the scalar's text, where goccy alone would canonicalise it.
	for in, want := range map[string]string{"!!str 0x10": "0x10", "!!str 1_000": "1_000", "!!str .inf": ".inf", "!!str &s 007": "007"} {
		var v struct {
			S string `yaml:"s"`
		}
		if err := DecodeYAML([]byte("s: "+in+"\n"), &v); err != nil || v.S != want {
			t.Errorf("%s: got %q, %v; want %q", in, v.S, err, want)
		}
	}
	var n struct {
		I int     `yaml:"i"`
		F float64 `yaml:"f"`
		B bool    `yaml:"b"`
	}
	if err := DecodeYAML([]byte("i: !!int 80\nf: !!float 2\nb: !!bool true\n"), &n); err != nil || n.I != 80 || n.F != 2 || !n.B {
		t.Errorf("got %+v, %v", n, err)
	}
}
