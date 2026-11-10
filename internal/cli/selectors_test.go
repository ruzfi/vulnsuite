package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/loader"
)

// selectorStore writes a templates tree exercising groups, classes, categories
// and a suites/ directory, and returns a loader.Store over it.
func selectorStore(t *testing.T) *loader.Store {
	t.Helper()
	root := t.TempDir()
	write := func(cat, id, meta string) {
		dir := filepath.Join(root, cat, id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		doc := fmt.Sprintf(`apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: %s
  summary: demo
  vuln_refs: [CVE-2026-1]%s
base: { kind: image, image: nginx:1, digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }
service: { ports: [ { container: 80, protocol: http } ] }
states: { vulnerable: { verify: [ { http: { path: /, status: 200 } } ] } }
`, id, meta)
		if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("web-apps", "php2shell-base", "\n  group: php2shell\n  primary: true\n  class: [vuln]")
	write("web-apps", "php2shell-waf", "\n  group: php2shell\n  variant: waf-evasion\n  class: [vuln]")
	write("network-services", "sshole-base", "\n  group: sshole\n  primary: true\n  class: [default-login]")
	write("network-services", "sshole-old", "\n  group: sshole\n  variant: old\n  class: [default-login]")
	write("misc", "misconf-a", "\n  class: [misconfig]")
	write("misc", "misconf-b", "\n  class: [misconfig]")
	write("misc", "plain-exposure", "\n  class: [exposure]")
	return loader.New(root)
}

// ids loads each path and returns the sorted set of ids, for order-insensitive
// assertions.
func idset(t *testing.T, s *loader.Store, paths []string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, p := range paths {
		out[loader.PeekID(p)] = true
	}
	return out
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveSelectorsAndFilters(t *testing.T) {
	s := selectorStore(t)
	ctx := context.Background()

	// Acceptance: -t sshole -t php2shell -class misconfig -> both primaries plus
	// every misconfig target, de-duplicated.
	var f filters
	f.class = multiFlag{"misconfig"}
	paths, err := resolveTargets(ctx, s, []string{"sshole", "php2shell"}, nil, false, false, f)
	if err != nil {
		t.Fatal(err)
	}
	got := idset(t, s, paths)
	want := []string{"sshole-base", "php2shell-base", "misconf-a", "misconf-b"}
	if len(paths) != len(want) {
		t.Fatalf("want %v, got %v", want, paths)
	}
	for _, id := range want {
		if !got[id] {
			t.Fatalf("missing %s in %v", id, got)
		}
	}
}

func TestResolveDedup(t *testing.T) {
	s := selectorStore(t)
	// A selector that also matches a filter must not start twice.
	var f filters
	f.class = multiFlag{"misconfig"}
	paths, err := resolveTargets(context.Background(), s, []string{"misconf-a"}, nil, false, false, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected misconf-a + misconf-b once each, got %v", paths)
	}
	// misconf-a (the selector) must sort before the filter matches.
	if loader.PeekID(paths[0]) != "misconf-a" {
		t.Fatalf("selector should lead: %v", paths)
	}
}

func TestResolveVariantsPropagate(t *testing.T) {
	s := selectorStore(t)
	// A group selector collapses to the primary by default...
	paths, err := resolveTargets(context.Background(), s, []string{"php2shell"}, nil, false, false, filters{})
	if err != nil || len(paths) != 1 {
		t.Fatalf("collapsed: %v %v", err, paths)
	}
	// ...and expands with -variants.
	paths, err = resolveTargets(context.Background(), s, []string{"php2shell"}, nil, false, true, filters{})
	if err != nil || len(paths) != 2 {
		t.Fatalf("expanded: %v %v", err, paths)
	}
}

func TestResolveFile(t *testing.T) {
	s := selectorStore(t)
	f := filepath.Join(t.TempDir(), "targets.txt")
	writeFile(t, f, "# my set\nphp2shell   # a group\nsshole\n-class misconfig\n")
	paths, err := resolveTargets(context.Background(), s, nil, []string{f}, false, false, filters{})
	if err != nil {
		t.Fatal(err)
	}
	got := idset(t, s, paths)
	for _, id := range []string{"php2shell-base", "sshole-base", "misconf-a", "misconf-b"} {
		if !got[id] {
			t.Fatalf("missing %s: %v", id, got)
		}
	}
	if got["php2shell-waf"] {
		t.Fatalf("variant should not appear without -variants: %v", got)
	}
}

func TestResolveSuite(t *testing.T) {
	s := selectorStore(t)
	writeFile(t, filepath.Join(s.Root, "suites", "web.txt"), "php2shell\nmisconf-a\n")

	// suite: expands its members; a group inside resolves to its primary.
	paths, err := resolveTargets(context.Background(), s, []string{"suite:web"}, nil, false, false, filters{})
	if err != nil {
		t.Fatal(err)
	}
	if got := idset(t, s, paths); !got["php2shell-base"] || !got["misconf-a"] || len(paths) != 2 {
		t.Fatalf("suite web: %v", got)
	}

	// -variants propagates into the suite's group handle.
	paths, err = resolveTargets(context.Background(), s, []string{"suite:web"}, nil, false, true, filters{})
	if err != nil {
		t.Fatal(err)
	}
	if got := idset(t, s, paths); !got["php2shell-waf"] || len(paths) != 3 {
		t.Fatalf("suite web -variants: %v", got)
	}

	// Unknown suite is an error.
	if _, err := resolveTargets(context.Background(), s, []string{"suite:nope"}, nil, false, false, filters{}); err == nil {
		t.Fatal("unknown suite should error")
	}
}

func TestResolveSuiteCycle(t *testing.T) {
	s := selectorStore(t)
	writeFile(t, filepath.Join(s.Root, "suites", "a.txt"), "suite:b\n")
	writeFile(t, filepath.Join(s.Root, "suites", "b.txt"), "suite:a\nplain-exposure\n")
	paths, err := resolveTargets(context.Background(), s, []string{"suite:a"}, nil, false, false, filters{})
	if err != nil {
		t.Fatalf("cycle should be broken, not error: %v", err)
	}
	if got := idset(t, s, paths); !got["plain-exposure"] || len(paths) != 1 {
		t.Fatalf("cycle: %v", got)
	}
}

func TestResolveFilterLineAnd(t *testing.T) {
	s := selectorStore(t)
	f := filepath.Join(t.TempDir(), "f.txt")
	// One line = one AND-filter: web-apps AND misconfig matches nothing.
	writeFile(t, f, "-category web-apps -class misconfig\n")
	paths, err := resolveTargets(context.Background(), s, nil, []string{f}, false, false, filters{})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("web-apps AND misconfig should be empty: %v", paths)
	}
	// Two lines union: misconfig OR exposure.
	writeFile(t, f, "-class misconfig\n-class exposure\n")
	paths, err = resolveTargets(context.Background(), s, nil, []string{f}, false, false, filters{})
	if err != nil {
		t.Fatal(err)
	}
	if got := idset(t, s, paths); !got["misconf-a"] || !got["misconf-b"] || !got["plain-exposure"] || len(paths) != 3 {
		t.Fatalf("misconfig OR exposure: %v", got)
	}
}

func TestResolveNothing(t *testing.T) {
	s := selectorStore(t)
	if _, err := resolveTargets(context.Background(), s, nil, nil, false, false, filters{}); err == nil {
		t.Fatal("no selectors/filters/all should be a usage error")
	}
}
