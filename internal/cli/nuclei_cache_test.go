package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// info indexes the nuclei-templates checkout once and caches the index under
// the user cache dir; run -q, which prints no scanner lines, does not index.
func TestNucleiIndexCachedAndSkippedUnderQuiet(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("LocalAppData", filepath.Join(home, "AppData", "Local"))
	t.Setenv("NUCLEI_TEMPLATES", "")
	cacheBase, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	cached := func() []string {
		m, _ := filepath.Glob(filepath.Join(cacheBase, "vulnsuite", "nuclei-index-*.json"))
		return m
	}
	nuclei := t.TempDir()
	tpl := filepath.Join(nuclei, "http", "cves", "2021", "CVE-2021-43798.yaml")
	if err := os.MkdirAll(filepath.Dir(tpl), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tpl, []byte("id: CVE-2021-43798\ninfo:\n  name: Grafana traversal\n  classification:\n    cve-id: CVE-2021-43798\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := fixtures(t)

	code, out, errOut := run(t, enginetest.New(), "-q", "-T", root, "run", "patched", "-t", "grafana", "-detach", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", nuclei)
	if code != ExitOK {
		t.Fatalf("run -q: %d\n%s\n%s", code, out, errOut)
	}
	if c := cached(); len(c) != 0 {
		t.Fatalf("run -q indexed the checkout: %v", c)
	}

	for i := 0; i < 2; i++ {
		code, out, errOut = run(t, nil, "-T", root, "info", "-nuclei-templates", nuclei, "grafana")
		if code != ExitOK || !strings.Contains(out, "http/cves/2021/CVE-2021-43798.yaml") {
			t.Fatalf("info #%d: %d\n%s\n%s", i, code, out, errOut)
		}
		if c := cached(); len(c) != 1 {
			t.Fatalf("info #%d: cache files %v", i, c)
		}
	}
}
