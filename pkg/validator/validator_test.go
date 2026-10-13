package validator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/loader"
	"github.com/ruzfi/vulnsuite/pkg/scanners"
)

func fixtures(t *testing.T) []*contract.Contract {
	t.Helper()
	root, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "templates"))
	s := loader.New(root)
	paths, err := s.All()
	if err != nil {
		t.Fatal(err)
	}
	cs, errs := s.LoadMany(paths)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	return cs
}

func rules(fs []Finding) map[string]Level {
	m := map[string]Level{}
	for _, f := range fs {
		m[f.Rule] = f.Level
	}
	return m
}

func TestFixturesAreClean(t *testing.T) {
	cs := fixtures(t)
	findings := (&Validator{AllowUnpinned: true}).CheckAll(cs)
	for _, f := range findings {
		if f.Level == Error {
			t.Errorf("unexpected error: %s", f)
		}
	}
	strict := (&Validator{}).CheckAll(cs)
	if rules(strict)["unpinned-base"] != Error {
		t.Fatal("unpinned base must be an error by default")
	}
}

func parse(t *testing.T, doc string) *contract.Contract {
	t.Helper()
	c, err := contract.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	c.Folder = t.TempDir()
	return c
}

const base = `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: lint-demo, summary: x, vuln_refs: [VS-X], references: [https://e.invalid] }
base: { kind: image, image: nginx:1, digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }
service: { ports: [ { container: 80, protocol: http } ], healthcheck: { tcp: { port: 80 }, timeout: 10s } }
states:
  vulnerable:
    verify: [ { http: { path: /, status: 200, body_matches: "x" } } ]
  patched:
    verify: [ { http: { path: /, status_in: [404] } } ]
`

func TestRules(t *testing.T) {
	v := &Validator{}
	// identical states, nothing distinguishes vulnerable from patched
	r := rules(v.Check(parse(t, base)))
	if r["identical-states"] != Warning {
		t.Fatalf("identical-states expected: %v", r)
	}
	// missing overlay file -> error; present -> states differ
	c := parse(t, strings.Replace(base, "  patched:\n", "  patched:\n    overlay: [ { src: files/x, dest: /etc/x } ]\n", 1))
	r = rules(v.Check(c))
	if r["missing-overlay"] != Error {
		t.Fatalf("missing-overlay expected: %v", r)
	}
	os.MkdirAll(filepath.Join(c.Folder, "files"), 0o755)
	os.WriteFile(filepath.Join(c.Folder, "files", "x"), []byte("1"), 0o644)
	r = rules(v.Check(c))
	if _, bad := r["missing-overlay"]; bad {
		t.Fatal("overlay now exists")
	}
	if _, bad := r["identical-states"]; bad {
		t.Fatal("states now differ")
	}
	// weak + empty verify
	c = parse(t, strings.Replace(base, `verify: [ { http: { path: /, status: 200, body_matches: "x" } } ]`, `verify: [ { http: { path: /, status: 200 } }, { http: { path: /x } } ]`, 1))
	r = rules(v.Check(c))
	if r["weak-verify"] != Warning || r["empty-verify"] != Error {
		t.Fatalf("verify rules: %v", r)
	}
	// bad regex
	c = parse(t, strings.Replace(base, `body_matches: "x"`, `body_matches: "("`, 1))
	if rules(v.Check(c))["bad-regex"] != Error {
		t.Fatal("bad-regex expected")
	}
	// patch on an image base
	c = parse(t, strings.Replace(base, "  patched:\n", "  patched:\n    patch: fix.patch\n", 1))
	r = rules(v.Check(c))
	if r["patch-needs-source"] != Error || r["missing-patch"] != Error {
		t.Fatalf("patch rules: %v", r)
	}
	// no patched state, no references, no healthcheck
	c = parse(t, `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: bare, summary: x }
base: { kind: build, context: src }
service: { ports: [ { container: 80 } ] }
states:
  vulnerable: {}
`)
	r = rules(v.Check(c))
	for _, want := range []string{"no-patched", "no-verify", "no-healthcheck", "no-vuln-ref", "no-references"} {
		if r[want] != Warning {
			t.Errorf("%s expected as warning: %v", want, r)
		}
	}
	if r["missing-context"] != Error {
		t.Fatal("missing build context must be an error")
	}
	// duplicate ids across a set
	a, b := parse(t, base), parse(t, base)
	if rules(v.CheckAll([]*contract.Contract{a, b}))["duplicate-id"] != Error {
		t.Fatal("duplicate-id expected")
	}
	e, w := Count(v.CheckAll([]*contract.Contract{a, b}))
	if e < 1 || w < 1 || Worst(v.Check(a)) != Warning {
		t.Fatalf("count/worst: %d %d", e, w)
	}
}

func TestRequiresRules(t *testing.T) {
	v := &Validator{}
	doc := strings.Replace(base, "service: { ports: [ { container: 80, protocol: http } ], healthcheck: { tcp: { port: 80 }, timeout: 10s } }",
		"service: { ports: [ { container: 80, protocol: http } ], devices: [\"/dev/kvm\"], healthcheck: { tcp: { port: 80 }, timeout: 10s } }", 1)
	if rules(v.Check(parse(t, doc)))["kvm-without-requires"] != Warning {
		t.Fatal("kvm-without-requires expected")
	}
	doc2 := strings.Replace(doc, "states:", "requires: { kvm: true, arch: [amd64] }\nstates:", 1)
	if _, bad := rules(v.Check(parse(t, doc2)))["kvm-without-requires"]; bad {
		t.Fatal("requires.kvm set should silence it")
	}
}

func TestFidelityRules(t *testing.T) {
	v := &Validator{}
	// unset -> warn
	if rules(v.Check(parse(t, base)))["fidelity-unset"] != Warning {
		t.Fatal("fidelity-unset expected")
	}
	// real + image base -> clean
	c := parse(t, strings.Replace(base, "metadata: { id: lint-demo,", "metadata: { fidelity: real, id: lint-demo,", 1))
	if _, bad := rules(v.Check(c))["fidelity-unset"]; bad {
		t.Fatal("real set, no warn")
	}
	// simulated + image base -> mismatch warn
	c = parse(t, strings.Replace(base, "metadata: { id: lint-demo,", "metadata: { fidelity: simulated, id: lint-demo,", 1))
	if rules(v.Check(c))["simulated-on-image-base"] != Warning {
		t.Fatal("simulated-on-image-base expected")
	}
	// simulated + build base -> fine
	c = parse(t, `apiVersion: vulnsuite/v1
kind: Target
metadata: { fidelity: simulated, id: sim, summary: x, vuln_refs: [VS-X], references: [https://e.invalid] }
base: { kind: build, context: src }
service: { ports: [ { container: 80, protocol: http } ], healthcheck: { tcp: { port: 80 }, timeout: 10s } }
states:
  vulnerable: { verify: [ { http: { path: /, status: 200, body_matches: x } } ] }
  patched: { verify: [ { http: { path: /, status_in: [404] } } ] }
`)
	if _, bad := rules(v.Check(c))["simulated-on-image-base"]; bad {
		t.Fatal("sim+build must not warn")
	}
}

func TestScannerLinkRules(t *testing.T) {
	v := &Validator{}
	// nothing linked, nothing declared -> warn
	c := parse(t, base)
	if rules(v.Check(c))["no-detected-by"] != Warning {
		t.Fatal("no-detected-by expected")
	}
	// custom-only silences it
	c = parse(t, strings.Replace(base, "metadata: { id: lint-demo,", "metadata: { detection: custom-only, id: lint-demo,", 1))
	if _, bad := rules(v.Check(c))["no-detected-by"]; bad {
		t.Fatal("custom-only must not warn")
	}
	// cross-check against a checkout
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "http"), 0o755)
	os.WriteFile(filepath.Join(root, "http", "x.yaml"), []byte("id: real-template\ninfo:\n  classification:\n    cve-id: CVE-2021-41773\n"), 0o644)
	idx, err := scanners.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	v = &Validator{Scanners: idx}
	c = parse(t, strings.Replace(base, "vuln_refs: [VS-X]", "vuln_refs: [CVE-2021-41773], detected_by: [\"nuclei:ghost\"]", 1))
	r := rules(v.Check(c))
	if r["unknown-scanner-template"] != Warning || r["undeclared-scanner-template"] != Warning {
		t.Fatalf("%v", r)
	}
	c = parse(t, strings.Replace(base, "vuln_refs: [VS-X]", "vuln_refs: [CVE-2021-41773], detected_by: [\"nuclei:real-template\"]", 1))
	r = rules(v.Check(c))
	for _, bad := range []string{"unknown-scanner-template", "undeclared-scanner-template", "no-detected-by"} {
		if _, ok := r[bad]; ok {
			t.Fatalf("%s should not fire: %v", bad, r)
		}
	}
}
