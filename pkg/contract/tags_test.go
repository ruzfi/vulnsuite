package contract

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// TestBadTagsRejected covers #145 item 1: a tag with no value, a tag that
// does not match its value, or a tag outside the core schema is a parse
// error, never a panic in goccy's decoder (the empty tags used to crash list,
// validate, info and run with SIGSEGV).
func TestBadTagsRejected(t *testing.T) {
	const base = "apiVersion: vulnsuite/v1\nkind: Target\nmetadata:\n  id: demo-tags\n  summary: x\n" +
		"  vuln_refs: [VS-DEMO-1]\nbase: { kind: image, image: nginx:1 }\nservice:\n  ports: [ { container: 80 } ]\n" +
		"states:\n  vulnerable:\n    verify: [ { tcp: { port: 80 } } ]\n"
	cases := map[string]string{
		// the issue's reproducers, in flow and block form
		"flow-local-tag":    strings.Replace(base, "metadata:\n", "metadata: {vuln_refs: !x}\nx:\n", 1),
		"flow-seq-tag":      base + "service: {ports: !!seq}\n",
		"flow-null-tag":     base + "metadata: {class: !!null}\n",
		"block-local":       strings.Replace(base, "  vuln_refs: [VS-DEMO-1]\n", "  vuln_refs: !x\n", 1),
		"block-local-mid":   strings.Replace(base, "  summary: x\n", "  vuln_refs: !x\n  summary: x\n", 1),
		"block-seq-empty":   strings.Replace(base, "  summary: x\n", "  class: !!seq\n  summary: x\n", 1),
		"block-map-sibling": strings.Replace(base, "  summary: x\n", "  verified_on: !!map\n  summary: x\n", 1),
		"block-str-null":    strings.Replace(base, "  summary: x\n", "  summary: !!str\n", 1),
		"local-tag-scalar":  strings.Replace(base, "  summary: x\n", "  summary: !x hello\n", 1),
		"binary":            strings.Replace(base, "  summary: x\n", "  summary: !!binary aGk=\n", 1),
		"timestamp":         strings.Replace(base, "  summary: x\n", "  summary: !!timestamp 2021-01-01\n", 1),
		"int-on-string":     strings.Replace(base, "  summary: x\n", "  summary: !!int x\n", 1),
		"tagged-key":        strings.Replace(base, "  summary: x\n", "  !x summary: x\n", 1),
		"seq-on-mapping":    strings.Replace(base, "  ports: [ { container: 80 } ]\n", "  ports: !!seq { container: 80 }\n", 1),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse panicked: %v", r)
				}
			}()
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatal("want an error")
			}
			var v any
			if err := DecodeYAML([]byte(doc), &v); err == nil {
				t.Fatal("DecodeYAML: want an error")
			}
		})
	}
}

// TestDecodeYAMLRecoversPanics: whatever the checks before it miss, a panic
// in goccy's decoder comes back from DecodeYAML (and Parse) as an error.
func TestDecodeYAMLRecoversPanics(t *testing.T) {
	var v struct {
		A []string `yaml:"a"`
	}
	err := unmarshal([]byte("a: [x]"), &v, nil, panicOption())
	if err == nil || !strings.Contains(err.Error(), "invalid YAML") {
		t.Fatalf("want a recovered error, got %v", err)
	}
}

func panicOption() yaml.DecodeOption {
	return func(*yaml.Decoder) error { panic("boom") }
}
