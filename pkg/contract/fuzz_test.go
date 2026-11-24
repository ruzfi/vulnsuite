package contract

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParse checks that no input makes Parse or DecodeYAML (the loader's
// peek) panic, as empty YAML tags once did in goccy's decoder (#145). The
// seed corpus is every contract in testdata plus the issue's reproducers.
// Run it with: go test ./pkg/contract -run '^$' -fuzz FuzzParse -fuzztime 60s
func FuzzParse(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*", "*.yaml"))
	for _, p := range files {
		data, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	for _, s := range []string{
		"metadata: {vuln_refs: !x}\n",
		"service: {ports: !!seq}\n",
		"metadata: {class: !!null}\n",
		"metadata:\n  vuln_refs: !x\n  summary: y\n",
		"metadata:\n  class: !!seq\n  summary: y\n",
		"a0: &m0 {k: v}\na1: &m1 {<<: [*m0, *m0, *m0, *m0]}\na2: {<<: [*m1, *m1, *m1, *m1]}\n",
		"states:\n  vulnerable:\n    verify:\n      - net: { port: 80, steps: [ { send: x, read: 1000000000000000 } ] }\n",
		"service:\n  healthcheck: { timeout: 99999999999999999999h }\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Parse(data)
		if err == nil && c == nil {
			t.Fatal("Parse returned neither a contract nor an error")
		}
		var peek struct {
			Metadata struct {
				ID       string   `yaml:"id"`
				VulnRefs []string `yaml:"vuln_refs"`
				Group    string   `yaml:"group"`
				Variant  string   `yaml:"variant"`
				Primary  bool     `yaml:"primary"`
			} `yaml:"metadata"`
		}
		_ = DecodeYAML(data, &peek)
	})
}
