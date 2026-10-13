package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimal = `apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: demo-target
  summary: demo
  vuln_refs: [CVE-2021-41773, VS-DEMO-1, GHSA-abcd-1234]
  severity: high
base:
  kind: image
  image: httpd:2.4.49
  digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
service:
  ports: [ { container: 80, protocol: http } ]
  command: "httpd-foreground"
  healthcheck: { http: { path: /, status: 200 }, timeout: 60s }
states:
  vulnerable:
    verify:
      - http: { raw_path: "/a/..%2e/etc/passwd", status: 200, body_matches: "root:" }
  patched:
    image: httpd:2.4.51
    verify:
      - http: { raw_path: "/a/..%2e/etc/passwd", status_in: [403, 404] }
`

func TestParseMinimal(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID() != "demo-target" || c.Base.Kind != BaseImage || !c.HasPatched() {
		t.Fatalf("unexpected contract %+v", c)
	}
	if got := c.Service.Command; len(got) != 1 || got[0] != "httpd-foreground" {
		t.Fatalf("string command not accepted: %v", got)
	}
	if c.Base.ImageRef() != "httpd:2.4.49@sha256:"+strings.Repeat("0", 64) {
		t.Fatalf("pinned ref: %s", c.Base.ImageRef())
	}
	if c.BuildKind("vulnerable") != BuildKindImage || c.BuildKind("patched") != BuildKindImage {
		t.Fatal("pure image states must not need a build")
	}
	if c.States["patched"].EffectiveImage(c.Base) != "httpd:2.4.51" {
		t.Fatal("per-state image override must win")
	}
	if c.ImageRef("vulnerable") != c.Base.ImageRef() {
		t.Fatal("image kind runs the base ref")
	}
	if ContainerName("a/b", "patched") != "vulnsuite-a-b-patched" {
		t.Fatal(ContainerName("a/b", "patched"))
	}
	id, st, ok := ParseContainerName("vulnsuite-demo-target-vulnerable")
	if !ok || id != "demo-target" || st != "vulnerable" {
		t.Fatalf("parse name: %q %q %v", id, st, ok)
	}
}

func TestFidelity(t *testing.T) {
	c, _ := Parse([]byte(minimal))
	if c.Fidelity() != FidelityReal || c.IsSimulated() {
		t.Fatal("default fidelity must be real")
	}
	doc := strings.Replace(minimal, "severity: high", "severity: high\n  fidelity: simulated", 1)
	c, err := Parse([]byte(doc))
	if err != nil || !c.IsSimulated() {
		t.Fatalf("simulated: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(minimal, "severity: high", "severity: high\n  fidelity: fake", 1))); err == nil {
		t.Fatal("bad fidelity must reject")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":   strings.Replace(minimal, "summary: demo", "summary: demo\n  bogus: 1", 1),
		"bad id":          strings.Replace(minimal, "id: demo-target", "id: Demo_Target", 1),
		"bad vuln ref":    strings.Replace(minimal, "VS-DEMO-1", "demo1", 1),
		"bad apiVersion":  strings.Replace(minimal, "vulnsuite/v1", "vulnsuite/v9", 1),
		"bad digest":      strings.Replace(minimal, "sha256:0000", "sha256:zz00", 1),
		"no ports":        strings.Replace(minimal, "ports: [ { container: 80, protocol: http } ]", "ports: []", 1),
		"two probe kinds": strings.Replace(minimal, "- http: { raw_path: \"/a/..%2e/etc/passwd\", status: 200, body_matches: \"root:\" }", "- { http: { path: / }, tcp: { port: 80 } }", 1),
		"unknown state":   strings.Replace(minimal, "  patched:", "  fixed:", 1),
		"image+context":   strings.Replace(minimal, "  image: httpd:2.4.49", "  image: httpd:2.4.49\n  context: src", 1),
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	legacy := strings.Replace(minimal, "vulnsuite/v1", "range.legacy/v2", 1)
	c, err := Parse([]byte(legacy))
	if err != nil || !c.IsLegacyAPIVersion() {
		t.Fatalf("legacy apiVersion must still load: %v", err)
	}
}

func TestContentHash(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "files"), 0o755)
	os.WriteFile(filepath.Join(dir, "files", "v.conf"), []byte("vuln"), 0o644)
	os.WriteFile(filepath.Join(dir, "files", "p.conf"), []byte("fixed"), 0o644)
	doc := `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: hash-demo, summary: x }
base: { kind: image, image: nginx:1 }
service: { ports: [ { container: 80, protocol: http } ] }
states:
  vulnerable:
    overlay: [ { src: files/v.conf, dest: /etc/x.conf } ]
  patched:
    overlay: [ { src: files/p.conf, dest: /etc/x.conf } ]
`
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	c.Folder = dir
	h1, h2 := c.ContentHash("vulnerable"), c.ContentHash("patched")
	if len(h1) != 12 || h1 == h2 {
		t.Fatalf("overlay content must change the hash: %s %s", h1, h2)
	}
	if c.ContentHash("vulnerable") != h1 {
		t.Fatal("hash must be stable")
	}
	if !strings.HasPrefix(c.ImageTag("vulnerable"), ImageRepoPrefix+"/hash-demo:vulnerable-") {
		t.Fatal(c.ImageTag("vulnerable"))
	}
	// same dest, same content -> same hash
	os.WriteFile(filepath.Join(dir, "files", "p.conf"), []byte("vuln"), 0o644)
	if c.ContentHash("vulnerable") != c.ContentHash("patched") {
		t.Fatal("identical overlay content must hash identically")
	}
	if c.BuildKind("vulnerable") != BuildKindOverlay {
		t.Fatal("overlay kind expected")
	}
}

func TestDurations(t *testing.T) {
	for in, want := range map[string]string{"60s": "1m0s", "5m": "5m0s", "1h": "1h0m0s", "": "1m0s"} {
		d, err := ParseDuration(in, 60e9)
		if err != nil || d.String() != want {
			t.Errorf("%q -> %v %v", in, d, err)
		}
	}
	if _, err := ParseDuration("10 seconds", 0); err == nil {
		t.Fatal("expected error")
	}
}
