package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveFromTemplates(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "cisa-kev.txt"),
		[]byte("# snapshot\nCVE-2021-41773\ncve-2017-5638 trailing\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	set, src, err := Resolve(context.Background(), Options{TemplatesDir: dir, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if src.Origin != OriginTemplates {
		t.Fatalf("origin = %q, want templates", src.Origin)
	}
	if set.Len() != 2 || !set.Contains("CVE-2021-41773") || !set.Contains("CVE-2017-5638") {
		t.Fatalf("set = %v", set)
	}
	// Case-insensitive and Any.
	if !set.Any([]string{"VS-X", "cve-2021-41773"}) {
		t.Fatal("Any should match case-insensitively")
	}
	if set.Any([]string{"CVE-2000-0001"}) {
		t.Fatal("Any matched a CVE not in the set")
	}
}

func TestResolveOfflineEmpty(t *testing.T) {
	// No templates file, no cache: an empty set, origin none, no error.
	set, src, err := Resolve(context.Background(), Options{TemplatesDir: t.TempDir(), CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if src.Origin != OriginNone || set.Len() != 0 {
		t.Fatalf("origin=%q len=%d, want none/0", src.Origin, set.Len())
	}
}

func TestRefreshFetchesAndCaches(t *testing.T) {
	feed := `{"vulnerabilities":[{"cveID":"CVE-2021-41773"},{"cveID":"CVE-2014-0160"},{"cveID":"bad"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != "vulnsuite" {
			t.Errorf("User-Agent = %q, want vulnsuite", ua)
		}
		w.Write([]byte(feed))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	opts := Options{
		TemplatesDir: t.TempDir(), // present but no data file; refresh must still fetch
		Refresh:      true,
		CacheDir:     cacheDir,
		Client:       srv.Client(),
		FeedURL:      srv.URL,
		Now:          func() time.Time { return time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	set, src, err := Resolve(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if src.Origin != OriginNetwork || !set.Contains("CVE-2021-41773") || !set.Contains("CVE-2014-0160") || set.Len() != 2 {
		t.Fatalf("network resolve: src=%+v set=%v", src, set)
	}
	// The cache was written; a non-refresh resolve with no templates file reads it.
	set2, src2, err := Resolve(context.Background(), Options{TemplatesDir: t.TempDir(), CacheDir: cacheDir})
	if err != nil {
		t.Fatal(err)
	}
	if src2.Origin != OriginCache || set2.Len() != 2 || src2.Fetched != "2024-01-02T03:04:05Z" {
		t.Fatalf("cache resolve: src=%+v set=%v", src2, set2)
	}
}

func TestTemplatesBeatsCache(t *testing.T) {
	// data/cisa-kev.txt (source of truth) wins over an existing cache.
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	os.MkdirAll(data, 0o755)
	os.WriteFile(filepath.Join(data, "cisa-kev.txt"), []byte("CVE-2021-41773\n"), 0o644)

	cacheDir := t.TempDir()
	if err := writeCache(filepath.Join(cacheDir, "cisa-kev.json"), Set{"CVE-2014-0160": true}, "network", "t"); err != nil {
		t.Fatal(err)
	}
	set, src, err := Resolve(context.Background(), Options{TemplatesDir: dir, CacheDir: cacheDir})
	if err != nil {
		t.Fatal(err)
	}
	if src.Origin != OriginTemplates || !set.Contains("CVE-2021-41773") || set.Contains("CVE-2014-0160") {
		t.Fatalf("templates should win: src=%+v set=%v", src, set)
	}
}
