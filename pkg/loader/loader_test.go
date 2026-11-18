package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func writeContract(t *testing.T, path, id string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf("apiVersion: vulnsuite/v1\nkind: Target\nmetadata: { id: %s, summary: x }\nbase: { kind: image, image: nginx:1 }\nservice: { ports: [ { container: 80 } ] }\nstates:\n  vulnerable:\n    verify: [ { tcp: { port: 80 } } ]\n", id)
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

func relPaths(t *testing.T, root string, paths []string) []string {
	t.Helper()
	var out []string
	for _, p := range paths {
		r, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, filepath.ToSlash(r))
	}
	return out
}

func TestDiscoveryWalkRules(t *testing.T) {
	root := t.TempDir()
	// A category named like a content dir is still discovered.
	writeContract(t, filepath.Join(root, "files", "a", "contract.yaml"), "cat-files")
	// Inside a contract folder, content dirs are not walked.
	writeContract(t, filepath.Join(root, "web", "b", "contract.yaml"), "web-b")
	writeContract(t, filepath.Join(root, "web", "b", "src", "contract.yaml"), "vendored-src")
	writeContract(t, filepath.Join(root, "web", "b", "files", "contract.yaml"), "vendored-files")
	// Dot-directories are never walked.
	writeContract(t, filepath.Join(root, ".github", "x", "contract.yaml"), "dot-github")
	writeContract(t, filepath.Join(root, "web", ".trash", "contract.yaml"), "dot-trash")
	// Two contract names in one folder load once (contract.yaml wins).
	writeContract(t, filepath.Join(root, "web", "c", "contract.yaml"), "web-c")
	writeContract(t, filepath.Join(root, "web", "c", "template.yaml"), "web-c")

	got, err := New(root).All()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"files/a/contract.yaml", "web/b/contract.yaml", "web/c/contract.yaml"}
	if fmt.Sprint(relPaths(t, root, got)) != fmt.Sprint(want) {
		t.Fatalf("All = %v, want %v", relPaths(t, root, got), want)
	}
}

func TestDiscoveryFollowsSymlinkedDirsWithoutLooping(t *testing.T) {
	outside, root := t.TempDir(), t.TempDir()
	writeContract(t, filepath.Join(outside, "t1", "contract.yaml"), "linked-one")
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// A loop back to the root must not recurse forever.
	if err := os.Symlink(root, filepath.Join(outside, "loop")); err != nil {
		t.Fatal(err)
	}
	got, err := New(root).All()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"linked/t1/contract.yaml"}; fmt.Sprint(relPaths(t, root, got)) != fmt.Sprint(want) {
		t.Fatalf("All = %v, want %v", relPaths(t, root, got), want)
	}
}

func TestFindSurfacesYAMLErrors(t *testing.T) {
	root := t.TempDir()
	writeContract(t, filepath.Join(root, "web", "ok", "contract.yaml"), "web-ok")
	bad := filepath.Join(root, "web", "broken", "contract.yaml")
	if err := os.MkdirAll(filepath.Dir(bad), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("metadata:\n  id: broken-one\n   summary: [unclosed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := New(root).Find("broken-one")
	if err == nil {
		t.Fatal("want an error")
	}
	if msg := err.Error(); !strings.Contains(msg, "could not be read") || !strings.Contains(msg, bad) {
		t.Fatalf("error must name the unparseable template: %v", err)
	}
	// A good selector is unaffected by an unrelated broken file.
	if p, err := New(root).Find("web-ok"); err != nil || len(p) != 1 {
		t.Fatalf("web-ok: %v %v", p, err)
	}
}

func TestShadowed(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"contract.yaml", "contract.yml", "notes.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := Shadowed(filepath.Join(dir, "contract.yaml"))
	if len(got) != 1 || filepath.Base(got[0]) != "contract.yml" {
		t.Fatalf("Shadowed = %v, want [contract.yml]", got)
	}
	found, err := New(dir).All()
	if err != nil || len(found) != 1 {
		t.Fatalf("discovery must still load one contract per folder: %v %v", found, err)
	}
}

// A bare selector is a template id/group/category, never a file or folder in
// the working directory; path-shaped selectors still reach the filesystem.
func TestFindBareSelectorIgnoresWorkingDirectory(t *testing.T) {
	s := testStore(t)
	cwd := t.TempDir()
	t.Chdir(cwd)
	// A stray file and a stray folder named like a template and a category.
	if err := os.WriteFile(filepath.Join(cwd, "grafana"), []byte("not a contract"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "iot"), 0o755); err != nil {
		t.Fatal(err)
	}
	p, err := s.Find("grafana")
	if err != nil || len(p) != 1 || peekID(p[0]) != "grafana-8.3.0-cve-2021-43798" {
		t.Fatalf("grafana with ./grafana present: %v %v", err, p)
	}
	if p, err := s.Find("iot"); err != nil || len(p) != 1 || peekID(p[0]) != "iot-camera-auth-bypass" {
		t.Fatalf("iot with ./iot present: %v %v", err, p)
	}

	// Path-shaped selectors still resolve against the working directory.
	src := filepath.Join(s.Root, "exposures", "exposed-dotenv-file", "contract.yaml")
	doc, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(cwd, "local")
	if err := os.Mkdir(local, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "contract.yaml"), doc, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "mine.yaml"), doc, 0o644); err != nil {
		t.Fatal(err)
	}
	want := func(sel, path string) {
		t.Helper()
		p, err := s.Find(sel)
		if err != nil || len(p) != 1 {
			t.Fatalf("%s: %v %v", sel, err, p)
		}
		if got, _ := filepath.EvalSymlinks(p[0]); got != mustEval(t, path) {
			t.Fatalf("%s: got %s, want %s", sel, p[0], path)
		}
	}
	want("./local", filepath.Join(local, "contract.yaml"))
	want(filepath.Join("local", "contract.yaml"), filepath.Join(local, "contract.yaml"))
	want("local/contract.yaml", filepath.Join(local, "contract.yaml"))
	want("mine.yaml", filepath.Join(cwd, "mine.yaml"))
	want(filepath.Join(cwd, "local"), filepath.Join(local, "contract.yaml"))
	// ./grafana is explicitly the stray file.
	if p, err := s.Find("./grafana"); err != nil || len(p) != 1 || filepath.Base(p[0]) != "grafana" {
		t.Fatalf("./grafana: %v %v", err, p)
	}
	// Root-relative paths keep working.
	if p, err := s.Find(filepath.Join("exposures", "exposed-dotenv-file")); err != nil || len(p) != 1 {
		t.Fatalf("root-relative: %v %v", err, p)
	}
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestIsPathSelector(t *testing.T) {
	for sel, want := range map[string]bool{
		"grafana": false, "web-servers": false, "CVE-2021-41773": false, "php2shell": false,
		"./grafana": true, ".": true, "~/t": true, "a/b": true, "contract.yaml": true, "x.YML": true,
		filepath.Join("a", "b"): true,
	} {
		if got := IsPathSelector(sel); got != want {
			t.Errorf("IsPathSelector(%q) = %v, want %v", sel, got, want)
		}
	}
}
