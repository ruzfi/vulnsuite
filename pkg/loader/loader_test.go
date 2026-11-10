package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	return New(root)
}

func TestAllAndLoad(t *testing.T) {
	s := testStore(t)
	paths, err := s.All()
	if err != nil || len(paths) != 6 {
		t.Fatalf("All: %v %v", err, paths)
	}
	c, err := s.LoadSelector("apache-httpd-2.4.49-cve-2021-41773")
	if err != nil {
		t.Fatal(err)
	}
	if c.Base.Kind != contract.BaseImage || c.Base.Image != "httpd:2.4.49" || c.BuildKind("vulnerable") != contract.BuildKindOverlay {
		t.Fatalf("apache: %+v", c.Base)
	}
	if c.Folder != filepath.Dir(c.SourcePath) || !filepath.IsAbs(c.Folder) {
		t.Fatalf("folder/source: %s %s", c.Folder, c.SourcePath)
	}
	g, err := s.LoadSelector("grafana-8.3.0-cve-2021-43798")
	if err != nil {
		t.Fatal(err)
	}
	if g.States["vulnerable"].EffectiveImage(g.Base) != "grafana/grafana:8.3.0" || g.States["patched"].EffectiveImage(g.Base) != "grafana/grafana:8.3.1" {
		t.Fatal("grafana version swap")
	}
	r, err := s.LoadSelector("redis-unauthenticated-access")
	if err != nil {
		t.Fatal(err)
	}
	if r.States["vulnerable"].Verify[0].Kind() != "tcp" || r.Service.PrimaryPort().Scheme() != "" {
		t.Fatal("redis is a raw tcp target")
	}
}

func TestFind(t *testing.T) {
	s := testStore(t)
	// by id
	if p, err := s.Find("iot-camera-auth-bypass"); err != nil || len(p) != 1 {
		t.Fatalf("by id: %v %v", err, p)
	}
	// by folder relative to root (a category)
	if p, err := s.Find("iot"); err != nil || len(p) != 1 {
		t.Fatalf("by folder: %v %v", err, p)
	}
	// by file
	if p, err := s.Find(filepath.Join(s.Root, "exposures", "exposed-dotenv-file", "contract.yaml")); err != nil || len(p) != 1 {
		t.Fatalf("by file: %v %v", err, p)
	}
	// unique substring
	if p, err := s.Find("grafana"); err != nil || len(p) != 1 {
		t.Fatalf("substring: %v %v", err, p)
	}
	// a ref-shaped selector resolves against vuln_refs when no id/file/folder
	// matches: the shared secondary CVE is in grafana and apache, in neither id.
	if p, err := s.Find("CVE-2026-109619"); err != nil || len(p) != 2 {
		t.Fatalf("by vuln_ref: %v %v", err, p)
	}
	// case-insensitive.
	if p, err := s.Find("cve-2026-109619"); err != nil || len(p) != 2 {
		t.Fatalf("by vuln_ref lowercase: %v %v", err, p)
	}
	// a ref-shaped selector with no vuln_ref match still errors.
	if _, err := s.Find("CVE-2000-0000"); err == nil {
		t.Fatal("expected not-found error for unmatched ref")
	}
	// ambiguous substring
	if _, err := s.Find("e"); err == nil {
		t.Fatal("expected ambiguity error")
	}
	if _, err := s.Find("does-not-exist"); err == nil {
		t.Fatal("expected not-found error")
	}
	many, err := s.FindMany([]string{"iot", "iot-camera-auth-bypass", "grafana"}, false, false)
	if err != nil || len(many) != 2 {
		t.Fatalf("FindMany dedup: %v %v", err, many)
	}
	byID, err := s.ByID()
	if err != nil || len(byID) != 6 {
		t.Fatalf("ByID: %v %d", err, len(byID))
	}
}

// groupStore writes a small templates tree with one three-member variant group
// (php2shell), one ungrouped target, and one single-member nickname group.
func groupStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	write := func(cat, id, extra string) {
		dir := filepath.Join(root, cat, id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		doc := fmt.Sprintf(`apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: %s
  summary: x%s
base: { kind: image, image: nginx:1, digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }
service: { ports: [ { container: 80, protocol: http } ] }
states:
  vulnerable:
    verify: [ { http: { path: /, status: 200 } } ]
`, id, extra)
		if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("web-apps", "php2shell-base", "\n  group: php2shell\n  primary: true")
	write("web-apps", "php2shell-waf", "\n  group: php2shell\n  variant: waf-evasion")
	write("web-apps", "php2shell-chunked", "\n  group: php2shell\n  variant: chunked")
	write("web-apps", "standalone", "")
	write("databases", "redis-rce", "\n  group: redis-nick")
	return New(root)
}

func TestGroupResolution(t *testing.T) {
	s := groupStore(t)

	// Exact id wins and resolves to just that target.
	if p, err := s.Find("php2shell-waf"); err != nil || len(p) != 1 {
		t.Fatalf("exact id: %v %v", err, p)
	}

	// A group selector resolves to the primary (one target).
	p, err := s.Find("php2shell")
	if err != nil || len(p) != 1 {
		t.Fatalf("group -> primary: %v %v", err, p)
	}
	if c, err := s.Load(p[0]); err != nil || c.ID() != "php2shell-base" {
		t.Fatalf("group primary should be php2shell-base: %v %v", err, c.ID())
	}

	// A single-member group (nickname) resolves to its lone member.
	if np, err := s.Find("redis-nick"); err != nil || len(np) != 1 {
		t.Fatalf("nickname: %v %v", err, np)
	}
}

func TestVariantsExpansion(t *testing.T) {
	s := groupStore(t)

	// Group selector, no variants -> primary only.
	if p, err := s.FindMany([]string{"php2shell"}, false, false); err != nil || len(p) != 1 {
		t.Fatalf("group collapsed: %v %v", err, p)
	}
	// Group selector, variants -> every member.
	if p, err := s.FindMany([]string{"php2shell"}, false, true); err != nil || len(p) != 3 {
		t.Fatalf("group expanded: %v %v", err, p)
	}
	// Exact variant id, variants set -> no-op, still one target.
	if p, err := s.FindMany([]string{"php2shell-waf"}, false, true); err != nil || len(p) != 1 {
		t.Fatalf("exact id with -variants: %v %v", err, p)
	}
}

func TestAllCollapse(t *testing.T) {
	s := groupStore(t)

	// -all without variants: primaries only (php2shell-base, standalone, redis-rce).
	prim, err := s.FindMany(nil, true, false)
	if err != nil || len(prim) != 3 {
		t.Fatalf("-all primaries-only: %v %v", err, prim)
	}
	// -all with variants: the full matrix (5 targets).
	full, err := s.FindMany(nil, true, true)
	if err != nil || len(full) != 5 {
		t.Fatalf("-all -variants: %v %v", err, full)
	}
}

func TestGroupMembers(t *testing.T) {
	s := groupStore(t)
	members, ok, err := s.GroupMembers("php2shell")
	if err != nil || !ok || len(members) != 3 {
		t.Fatalf("GroupMembers: %v %v %v", err, ok, members)
	}
	if !members[0].Primary || members[0].ID != "php2shell-base" {
		t.Fatalf("primary should sort first: %+v", members[0])
	}
	if _, ok, _ := s.GroupMembers("nope"); ok {
		t.Fatal("unknown handle should not be ok")
	}
}

func TestGroupNoPrimaryError(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"g-a", "g-b"} {
		dir := filepath.Join(root, "web-apps", id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		doc := fmt.Sprintf(`apiVersion: vulnsuite/v1
kind: Target
metadata: { id: %s, summary: x, group: g, variant: %s }
base: { kind: image, image: nginx:1 }
service: { ports: [ { container: 80 } ] }
states: { vulnerable: { verify: [ { http: { path: /, status: 200 } } ] } }
`, id, id)
		if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := New(root)
	if _, err := s.Find("g"); err == nil {
		t.Fatal("a group with no primary should fail to resolve")
	}
}
