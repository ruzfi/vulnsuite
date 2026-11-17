package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// kevRoot is a one-template tree whose data/cisa-kev.txt carries catalog
// version ver, with the user cache dir isolated from the developer's machine.
func kevRoot(t *testing.T, ver string) (root, cacheFile string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	root = t.TempDir()
	src := filepath.Join(fixtures(t), "web-servers", "apache-httpd-2.4.49-cve-2021-41773", "contract.yaml")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(root, "web-servers", "apache", "contract.yaml")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
	snap := "# catalogVersion: " + ver + "  count: 1\nCVE-2021-41773\n"
	if err := os.MkdirAll(filepath.Join(root, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data", "cisa-kev.txt"), []byte(snap), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(cacheDir, "vulnsuite", "cisa-kev.json")
}

func TestListShowsKEVAgeAndWarnsWhenStale(t *testing.T) {
	root, _ := kevRoot(t, "2020.01.15")
	code, out, errOut := run(t, nil, "-T", root, "list")
	if code != ExitOK {
		t.Fatalf("list: %d %s", code, errOut)
	}
	if !strings.Contains(out, "KEV source: templates ") || !strings.Contains(out, "catalog 2020.01.15") || !strings.Contains(out, "days old") {
		t.Fatalf("status line: %s", out)
	}
	if !strings.Contains(errOut, "warning: the KEV data is") || !strings.Contains(errOut, "-refresh-kev") {
		t.Fatalf("stale warning missing: %q", errOut)
	}

	code, out, _ = run(t, nil, "-T", root, "-json", "list")
	if code != ExitOK {
		t.Fatal(code)
	}
	var rows []struct {
		ID        string `json:"id"`
		KEV       *bool  `json:"kev"`
		KEVSource *struct {
			Origin         string `json:"origin"`
			CatalogVersion string `json:"catalog_version"`
			AsOf           string `json:"as_of"`
			AgeDays        *int   `json:"age_days"`
			Stale          bool   `json:"stale"`
		} `json:"kev_source"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("-json is still an array of rows: %v\n%s", err, out)
	}
	if len(rows) != 1 || rows[0].KEVSource == nil {
		t.Fatalf("rows: %s", out)
	}
	ks := rows[0].KEVSource
	if ks.Origin != "templates" || ks.CatalogVersion != "2020.01.15" || ks.AsOf != "2020-01-15" || !ks.Stale || ks.AgeDays == nil || *ks.AgeDays < 30 {
		t.Fatalf("kev_source: %+v", ks)
	}
}

func TestListPrefersFresherKEVCache(t *testing.T) {
	root, cache := kevRoot(t, "2020.01.15")
	today := time.Now().UTC()
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	doc := `{"fetched":"` + today.Format(time.RFC3339) + `","source":"network","catalog_version":"` + today.Format("2006.01.02") + `","cves":["CVE-2014-0160"]}`
	if err := os.WriteFile(cache, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, nil, "-T", root, "list")
	if code != ExitOK {
		t.Fatalf("list: %d %s", code, errOut)
	}
	if !strings.Contains(out, "KEV source: cache ") || !strings.Contains(out, "current as of today") {
		t.Fatalf("the fresher cache should win: %s", out)
	}
	if strings.Contains(errOut, "warning: the KEV data") {
		t.Fatalf("fresh data must not warn: %s", errOut)
	}
}
