package validator

import (
	"fmt"
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
	// #119: cpu_flags rule emulation out, so emulation: true contradicts them.
	flags := strings.Replace(base, "states:", "requires: { arch: [amd64], cpu_flags: [avx512vbmi], emulation: true }\nstates:", 1)
	if rules(v.Check(parse(t, flags)))["cpu-flags-with-emulation"] != Warning {
		t.Fatal("cpu-flags-with-emulation expected")
	}
	for _, req := range []string{"{ arch: [amd64], cpu_flags: [avx512vbmi] }", "{ arch: [amd64], cpu_flags: [avx512vbmi], emulation: false }", "{ emulation: true }"} {
		doc := strings.Replace(base, "states:", "requires: "+req+"\nstates:", 1)
		if _, bad := rules(v.Check(parse(t, doc)))["cpu-flags-with-emulation"]; bad {
			t.Fatalf("cpu-flags-with-emulation on %s", req)
		}
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

// groupMember builds a minimal valid contract for variant-group tests.
func groupMember(t *testing.T, id, group, variant string, primary bool, refs string) *contract.Contract {
	t.Helper()
	prim := ""
	if primary {
		prim = "\n  primary: true"
	}
	vr := ""
	if variant != "" {
		vr = "\n  variant: " + variant
	}
	doc := fmt.Sprintf(`apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: %s
  summary: x
  vuln_refs: [%s]
  references: [https://e.invalid]
  group: %s%s%s
base: { kind: image, image: nginx:1, digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }
service: { ports: [ { container: 80, protocol: http } ], healthcheck: { tcp: { port: 80 }, timeout: 10s } }
states:
  vulnerable:
    verify: [ { http: { path: /, status: 200, body_matches: "x" } } ]
  patched:
    verify: [ { http: { path: /, status_in: [404] } } ]
`, id, refs, group, prim, vr)
	return parse(t, doc)
}

func TestGroupChecks(t *testing.T) {
	v := &Validator{}

	// Healthy group: one primary, unique variants, shared refs.
	ok := []*contract.Contract{
		groupMember(t, "php2shell-base", "php2shell", "", true, "CVE-2026-0001"),
		groupMember(t, "php2shell-waf", "php2shell", "waf-evasion", false, "CVE-2026-0001"),
		groupMember(t, "php2shell-chunked", "php2shell", "chunked", false, "CVE-2026-0001"),
	}
	for rule := range rules(v.CheckAll(ok)) {
		if strings.HasPrefix(rule, "group-") {
			t.Fatalf("healthy group fired %s", rule)
		}
	}

	// Single-member group (nickname): no primary needed, no variant needed.
	nick := []*contract.Contract{groupMember(t, "redis-rce", "redis-nick", "", false, "CVE-2026-0002")}
	for rule := range rules(v.CheckAll(nick)) {
		if strings.HasPrefix(rule, "group-") {
			t.Fatalf("nickname fired %s", rule)
		}
	}

	// Zero primaries.
	none := []*contract.Contract{
		groupMember(t, "g-a", "g", "a", false, "CVE-2026-0003"),
		groupMember(t, "g-b", "g", "b", false, "CVE-2026-0003"),
	}
	if rules(v.CheckAll(none))["group-no-primary"] != Error {
		t.Fatal("zero primaries must be an error")
	}

	// Multiple primaries.
	two := []*contract.Contract{
		groupMember(t, "g-a", "g", "a", true, "CVE-2026-0003"),
		groupMember(t, "g-b", "g", "b", true, "CVE-2026-0003"),
	}
	if rules(v.CheckAll(two))["group-multiple-primaries"] != Error {
		t.Fatal("two primaries must be an error")
	}

	// Duplicate variant.
	dup := []*contract.Contract{
		groupMember(t, "g-a", "g", "same", true, "CVE-2026-0003"),
		groupMember(t, "g-b", "g", "same", false, "CVE-2026-0003"),
	}
	if rules(v.CheckAll(dup))["group-duplicate-variant"] != Error {
		t.Fatal("duplicate variant must be an error")
	}

	// Non-primary member without a variant.
	missing := []*contract.Contract{
		groupMember(t, "g-a", "g", "", true, "CVE-2026-0003"),
		groupMember(t, "g-b", "g", "", false, "CVE-2026-0003"),
	}
	if rules(v.CheckAll(missing))["group-variant-missing"] != Error {
		t.Fatal("missing variant on a non-primary member must be an error")
	}

	// Divergent vuln_refs: a soft warning.
	diverge := []*contract.Contract{
		groupMember(t, "g-a", "g", "a", true, "CVE-2026-0003"),
		groupMember(t, "g-b", "g", "b", false, "CVE-2026-0009"),
	}
	if rules(v.CheckAll(diverge))["group-divergent-refs"] != Warning {
		t.Fatal("divergent refs must warn")
	}

	// group handle equal to a template id.
	collide := []*contract.Contract{
		groupMember(t, "php2shell", "other", "", true, "CVE-2026-0003"),
		groupMember(t, "other-a", "other", "a", false, "CVE-2026-0003"),
	}
	// add a contract whose id equals the handle "other"
	collide = append(collide, groupMember(t, "other", "solo", "", false, "CVE-2026-0003"))
	if rules(v.CheckAll(collide))["group-id-collision"] != Error {
		t.Fatal("group handle equal to an id must be an error")
	}
}

func TestGroupMultiCategory(t *testing.T) {
	cat := map[string]string{"web-g-a": "web-apps", "db-g-b": "databases"}
	v := &Validator{CategoryOf: func(c *contract.Contract) string { return cat[c.ID()] }}
	members := []*contract.Contract{
		groupMember(t, "web-g-a", "g", "a", true, "CVE-2026-0003"),
		groupMember(t, "db-g-b", "g", "b", false, "CVE-2026-0003"),
	}
	if rules(v.CheckAll(members))["group-multi-category"] != Warning {
		t.Fatal("a group spanning two categories must warn")
	}
}

func TestIdenticalStatesSeesSidecarsAndSeed(t *testing.T) {
	v := &Validator{}
	withSidecar := strings.Replace(base, "healthcheck:", "sidecars: [ { name: db, image: \"mysql:8.0.1\" } ], healthcheck:", 1)
	// Same main image, but patched swaps the sidecar to the fixed release.
	c := parse(t, strings.Replace(withSidecar, "  patched:\n", "  patched:\n    sidecars: { db: { image: \"mysql:8.0.2\" } }\n", 1))
	if _, bad := rules(v.Check(c))["identical-states"]; bad {
		t.Fatal("states that differ only in a sidecar override must not be identical")
	}
	// An override to the same image is still identical.
	c = parse(t, strings.Replace(withSidecar, "  patched:\n", "  patched:\n    sidecars: { db: { image: \"mysql:8.0.1\" } }\n", 1))
	if rules(v.Check(c))["identical-states"] != Warning {
		t.Fatal("a no-op sidecar override must still warn")
	}
	// Different seed data.
	c = parse(t, strings.Replace(base, "  patched:\n", "  patched:\n    seed: [ { run: \"echo fixed\" } ]\n", 1))
	if _, bad := rules(v.Check(c))["identical-states"]; bad {
		t.Fatal("states that differ only in seed must not be identical")
	}
}

func TestPrimaryWithoutGroup(t *testing.T) {
	v := &Validator{}
	c := parse(t, strings.Replace(base, "summary: x,", "summary: x, primary: true,", 1))
	if rules(v.Check(c))["primary-no-group"] != Warning {
		t.Fatal("primary without group must warn")
	}
	if _, bad := rules(v.Check(parse(t, base)))["primary-no-group"]; bad {
		t.Fatal("no primary, no warning")
	}
}

func TestUndeclaredPortRefs(t *testing.T) {
	v := &Validator{}
	if l, ok := rules(v.Check(parse(t, base)))["undeclared-port"]; ok {
		t.Fatalf("declared ports flagged: %v", l)
	}
	cases := map[string]string{
		"healthcheck": strings.Replace(base, "tcp: { port: 80 }", "tcp: { port: 8080 }", 1),
		"http":        strings.Replace(base, "{ http: { path: /, status: 200,", "{ http: { port: 8443, path: /, status: 200,", 1),
		"tcp":         strings.Replace(base, `[ { http: { path: /, status_in: [404] } } ]`, `[ { tcp: { port: 22 } } ]`, 1),
		"net":         strings.Replace(base, `[ { http: { path: /, status_in: [404] } } ]`, `[ { net: { port: 25, steps: [ { expect: "220" } ] } } ]`, 1),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if doc == base {
				t.Fatal("replacement did not apply")
			}
			fs := v.Check(parse(t, doc))
			if rules(fs)["undeclared-port"] != Warning {
				t.Fatalf("want undeclared-port warning, got %v", fs)
			}
		})
	}
	// Proving a port is closed needs no declaration.
	closed := strings.Replace(base, `[ { http: { path: /, status_in: [404] } } ]`, `[ { tcp: { port: 9229, closed: true } } ]`, 1)
	if _, ok := rules(v.Check(parse(t, closed)))["undeclared-port"]; ok {
		t.Fatal("tcp closed: true must not need a declared port")
	}
}

func TestShadowedContract(t *testing.T) {
	c := parse(t, base)
	c.SourcePath = filepath.Join(c.Folder, "contract.yaml")
	for _, n := range []string{"contract.yaml", "template.yaml"} {
		if err := os.WriteFile(filepath.Join(c.Folder, n), []byte(base), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fs := (&Validator{}).Check(c)
	if rules(fs)["shadowed-contract"] != Warning {
		t.Fatalf("want shadowed-contract warning, got %v", fs)
	}
	if err := os.Remove(filepath.Join(c.Folder, "template.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, ok := rules((&Validator{}).Check(c))["shadowed-contract"]; ok {
		t.Fatal("a lone contract must not be reported as shadowed")
	}
}

// Issue #93 item 2: on a source base, one state with a patch is enough; the
// warning is for states that cannot differ at all.
func TestSourceNoDiff(t *testing.T) {
	head := pinHead + "base: { kind: source, repo: https://example.invalid/x.git, commit: 0123456789abcdef0123456789abcdef01234567 }\nstates:\n"
	cases := []struct {
		name, states string
		warn         bool
	}{
		{"patched has the patch", "  vulnerable: {}\n  patched: { patch: patches/fix.patch }\n", false},
		{"vulnerable has the patch", "  vulnerable: { patch: patches/vuln.patch }\n  patched: {}\n", false},
		{"patched has an overlay", "  vulnerable: {}\n  patched: { overlay: [ { src: files/x, dest: conf/x } ] }\n", false},
		{"no difference", "  vulnerable: {}\n  patched: {}\n", true},
		{"no patched state", "  vulnerable: {}\n", false},
	}
	for _, tc := range cases {
		got := findingsFor((&Validator{}).Check(parse(t, head+tc.states)), "source-no-diff")
		if (len(got) > 0) != tc.warn {
			t.Errorf("%s: source-no-diff = %v, want warning %v", tc.name, got, tc.warn)
		}
	}
}

// Issue #93 item 6: a build context needs no Dockerfile of its own when every
// state overlays one into the context; the builder reads generated files first.
func TestMissingDockerfileOverlaid(t *testing.T) {
	doc := func(vuln, patched string) string {
		return pinHead + "base: { kind: build, context: src }\nstates:\n" +
			"  vulnerable: { overlay: [ " + vuln + " ] }\n  patched: { overlay: [ " + patched + " ] }\n"
	}
	own := "{ src: files/Dockerfile, dest: Dockerfile }"
	other := "{ src: files/x, dest: etc/x }"
	cases := []struct {
		name, doc string
		lacking   string // "" = no finding
	}{
		{"every state overlays it", doc(own, "{ src: files/Dockerfile, dest: ./Dockerfile }"), ""},
		{"one state does not", doc(own, other), "patched"},
		{"none does", doc(other, other), "build context has no Dockerfile"},
	}
	for _, tc := range cases {
		c := parse(t, tc.doc)
		os.MkdirAll(filepath.Join(c.Folder, "src"), 0o755)
		os.MkdirAll(filepath.Join(c.Folder, "files"), 0o755)
		os.WriteFile(filepath.Join(c.Folder, "files", "Dockerfile"), []byte("FROM scratch\n"), 0o644)
		os.WriteFile(filepath.Join(c.Folder, "files", "x"), []byte("x"), 0o644)
		got := findingsFor((&Validator{}).Check(c), "missing-dockerfile")
		switch {
		case tc.lacking == "" && len(got) > 0:
			t.Errorf("%s: unexpected %v", tc.name, got)
		case tc.lacking != "" && (len(got) != 1 || !strings.Contains(got[0].Message, tc.lacking)):
			t.Errorf("%s: want one missing-dockerfile naming %q, got %v", tc.name, tc.lacking, got)
		}
	}
}

func TestVerificationRules(t *testing.T) {
	v := &Validator{}
	withMeta := func(meta, extra string) *contract.Contract {
		return parse(t, strings.Replace(base, "metadata: { id: lint-demo,", "metadata: { "+meta+" id: lint-demo,", 1)+extra)
	}
	// default (verified, no requires): nothing
	r := rules(v.Check(parse(t, base)))
	for _, rule := range []string{"unverified-target", "verified-no-evidence", "verified-on-stale"} {
		if _, bad := r[rule]; bad {
			t.Errorf("plain contract: unexpected %s", rule)
		}
	}
	// unverified: a warning, and every other rule still runs
	r = rules(v.Check(withMeta("verification: unverified,", "")))
	if r["unverified-target"] != Warning {
		t.Error("unverified-target warning expected")
	}
	if r["identical-states"] != Warning {
		t.Error("an unverified target must still get the other rules (identical-states)")
	}
	// explicitly verified, host-specific requires, no evidence
	cpu := "requires: { cpu_flags: [avx512vbmi] }\n"
	if rules(v.Check(withMeta("verification: verified,", cpu)))["verified-no-evidence"] != Warning {
		t.Error("verified-no-evidence expected")
	}
	// the default does not trip it: only an explicit claim does
	if _, bad := rules(v.Check(withMeta("", cpu)))["verified-no-evidence"]; bad {
		t.Error("verified-no-evidence must need an explicit verification: verified")
	}
	stamp := func(flags, states string) string {
		return `verification: verified, verified_on: { date: "2026-11-21", vulnsuite: v0.4.0, host: linux/amd64, cpu_flags: [` +
			flags + `], states: [` + states + `] },`
	}
	r = rules(v.Check(withMeta(stamp("avx512vbmi", "vulnerable, patched"), cpu)))
	for _, rule := range []string{"verified-no-evidence", "verified-on-stale"} {
		if _, bad := r[rule]; bad {
			t.Errorf("full stamp: unexpected %s", rule)
		}
	}
	// a cpu flag added after the stamp, and a state the stamp names but the
	// template dropped, are stale evidence
	if rules(v.Check(withMeta(stamp("", "vulnerable"), cpu)))["verified-on-stale"] != Warning {
		t.Error("verified-on-stale expected for an unchecked cpu flag")
	}
	noPatched := strings.Replace(base, "  patched:\n    verify: [ { http: { path: /, status_in: [404] } } ]\n", "", 1)
	c := parse(t, strings.Replace(noPatched, "metadata: { id: lint-demo,", "metadata: { "+stamp("", "vulnerable, patched")+" id: lint-demo,", 1))
	if rules(v.Check(c))["verified-on-stale"] != Warning {
		t.Error("verified-on-stale expected for an undeclared state")
	}
}
