package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	if err := writeCache(filepath.Join(cacheDir, "cisa-kev.json"), Set{"CVE-2014-0160": true}, "network", "t", ""); err != nil {
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

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptCacheTreatedAsMissing(t *testing.T) {
	cache := t.TempDir()
	writeFile(t, filepath.Join(cache, "cisa-kev.json"), `{"fetched":"x","cves":["CVE-2021-`)
	var warned []string
	set, src, err := Resolve(context.Background(), Options{
		TemplatesDir: t.TempDir(), CacheDir: cache,
		Warn: func(m string) { warned = append(warned, m) },
	})
	if err != nil {
		t.Fatalf("corrupt cache must not fail Resolve: %v", err)
	}
	if src.Origin != OriginNone || set.Len() != 0 {
		t.Fatalf("origin=%q len=%d, want none/0", src.Origin, set.Len())
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "corrupt KEV cache") {
		t.Fatalf("warnings = %q", warned)
	}
}

func TestEmptyTemplatesSnapshotFallsThroughToCache(t *testing.T) {
	tpl, cache := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(tpl, "data", "cisa-kev.txt"), "# header only\n\n")
	if err := writeCache(filepath.Join(cache, "cisa-kev.json"), Set{"CVE-2014-0160": true}, "network", "2026-01-01T00:00:00Z", ""); err != nil {
		t.Fatal(err)
	}
	var warned []string
	set, src, err := Resolve(context.Background(), Options{
		TemplatesDir: tpl, CacheDir: cache,
		Warn: func(m string) { warned = append(warned, m) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if src.Origin != OriginCache || !set.Contains("CVE-2014-0160") {
		t.Fatalf("origin=%q set=%v, want the cache", src.Origin, set)
	}
	if len(warned) != 1 {
		t.Fatalf("warnings = %q, want one about the empty snapshot", warned)
	}
}

func TestWriteCacheAtomicLeavesNoTemp(t *testing.T) {
	cache := t.TempDir()
	path := filepath.Join(cache, "cisa-kev.json")
	writeFile(t, path, "old")
	if err := writeCache(path, Set{"CVE-2021-41773": true}, "network", "now", ""); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "cisa-kev.json" {
		t.Fatalf("cache dir = %v, want only cisa-kev.json", ents)
	}
	set, _, err := loadCache(path)
	if err != nil || !set.Contains("CVE-2021-41773") {
		t.Fatalf("reload: set=%v err=%v", set, err)
	}
}

func TestCVERegexesAnchored(t *testing.T) {
	got := parseTxt([]byte("CVE-2021-12345678\nxCVE-2020-1111\nCVE-2019-0001, cve-2018-12345\n"))
	if got.Len() != 2 || !got.Contains("CVE-2019-0001") || !got.Contains("CVE-2018-12345") {
		t.Fatalf("parseTxt = %v", got)
	}
	cache := filepath.Join(t.TempDir(), "cisa-kev.json")
	writeFile(t, cache, `{"cves":["CVE-2021-1234-junk","CVE-2021-1234"," CVE-2000-0001"]}`)
	set, _, err := loadCache(cache)
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 || !set.Contains("CVE-2021-1234") {
		t.Fatalf("loadCache = %v", set)
	}
}

func TestFresherCacheBeatsStaleTemplates(t *testing.T) {
	tpl := t.TempDir()
	writeFile(t, filepath.Join(tpl, "data", "cisa-kev.txt"), "# catalogVersion: 2026.01.10  count: 1\nCVE-2021-41773\n")
	cases := []struct {
		name, cacheVersion, fetched string
		want                        Origin
	}{
		{"newer catalog in cache", "2026.03.01", "2026-03-01T08:00:00Z", OriginCache},
		{"older catalog in cache", "2025.12.01", "2026-03-01T08:00:00Z", OriginTemplates},
		{"same catalog", "2026.01.10", "2026-01-11T08:00:00Z", OriginTemplates},
		{"old cache without catalog version, fetched later", "", "2026-02-01T00:00:00Z", OriginCache},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := t.TempDir()
			if err := writeCache(filepath.Join(cache, "cisa-kev.json"), Set{"CVE-2014-0160": true}, "network", tc.fetched, tc.cacheVersion); err != nil {
				t.Fatal(err)
			}
			_, src, err := Resolve(context.Background(), Options{TemplatesDir: tpl, CacheDir: cache})
			if err != nil {
				t.Fatal(err)
			}
			if src.Origin != tc.want {
				t.Fatalf("origin %q, want %q (%+v)", src.Origin, tc.want, src)
			}
		})
	}
	// A snapshot with no catalogVersion header cannot be dated: a cache that
	// can be dated (a -refresh-kev) wins over it, as USAGE.md promises.
	plain := t.TempDir()
	writeFile(t, filepath.Join(plain, "data", "cisa-kev.txt"), "CVE-2021-41773\n")
	cache := t.TempDir()
	_ = writeCache(filepath.Join(cache, "cisa-kev.json"), Set{"CVE-2014-0160": true}, "network", "2026-03-01T08:00:00Z", "2026.03.01")
	if set, src, _ := Resolve(context.Background(), Options{TemplatesDir: plain, CacheDir: cache}); src.Origin != OriginCache || !set.Contains("CVE-2014-0160") {
		t.Fatalf("undated snapshot vs dated cache: %+v", src)
	}
	// Neither can be dated: the snapshot stays the source of truth.
	undated := t.TempDir()
	_ = writeCache(filepath.Join(undated, "cisa-kev.json"), Set{"CVE-2014-0160": true}, "network", "", "")
	if _, src, _ := Resolve(context.Background(), Options{TemplatesDir: plain, CacheDir: undated}); src.Origin != OriginTemplates {
		t.Fatalf("undated snapshot vs undated cache: %+v", src)
	}
}

// A cache that is valid JSON but holds no CVE ids is not a catalog: it is
// ignored with a warning, exactly like a corrupt one, rather than used as an
// empty catalog (KEV "-" everywhere, -no-kev matching everything).
func TestIDLessCacheTreatedAsMissing(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"fetched":"2026-03-01T08:00:00Z","cves":[]}`, `{"cves":["bad","CVE-21-1"]}`} {
		t.Run(body, func(t *testing.T) {
			cache := t.TempDir()
			writeFile(t, filepath.Join(cache, "cisa-kev.json"), body)
			var warned []string
			set, src, err := Resolve(context.Background(), Options{
				TemplatesDir: t.TempDir(), CacheDir: cache,
				Warn: func(m string) { warned = append(warned, m) },
			})
			if err != nil {
				t.Fatal(err)
			}
			if src.Origin != OriginNone || set.Len() != 0 {
				t.Fatalf("origin=%q len=%d, want none/0", src.Origin, set.Len())
			}
			if len(warned) != 1 || !strings.Contains(warned[0], "no CVE ids") {
				t.Fatalf("warnings = %q", warned)
			}
		})
	}
	// Nor does an id-less cache shadow a dated snapshot or count as newer.
	tpl, cache := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(tpl, "data", "cisa-kev.txt"), "# catalogVersion: 2026.01.10\nCVE-2021-41773\n")
	writeFile(t, filepath.Join(cache, "cisa-kev.json"), `{"fetched":"2026-03-01T08:00:00Z","catalog_version":"2026.03.01","cves":[]}`)
	if _, src, _ := Resolve(context.Background(), Options{TemplatesDir: tpl, CacheDir: cache, Warn: func(string) {}}); src.Origin != OriginTemplates {
		t.Fatalf("id-less cache beat the snapshot: %+v", src)
	}
}

// A refresh whose cache write fails still returns the fresh set, and warns.
func TestRefreshWarnsWhenCacheWriteFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-41773"}]}`))
	}))
	defer srv.Close()
	// The cache directory is a regular file, so it cannot be created.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	writeFile(t, blocker, "x")
	var warned []string
	set, src, err := Resolve(context.Background(), Options{
		Refresh: true, CacheDir: blocker, Client: srv.Client(), FeedURL: srv.URL,
		Warn: func(m string) { warned = append(warned, m) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if src.Origin != OriginNetwork || !set.Contains("CVE-2021-41773") {
		t.Fatalf("src=%+v set=%v", src, set)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "could not write the KEV cache") {
		t.Fatalf("warnings = %q", warned)
	}
}

func TestSourceAgeAndStale(t *testing.T) {
	tpl := t.TempDir()
	writeFile(t, filepath.Join(tpl, "data", "cisa-kev.txt"), "# catalogVersion: 2026.10.01  count: 1\nCVE-2021-41773\n")
	_, src, err := Resolve(context.Background(), Options{TemplatesDir: tpl, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if src.CatalogVersion != "2026.10.01" || !src.AsOf.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("source %+v", src)
	}
	if !strings.Contains(src.String(), "catalog 2026.10.01") {
		t.Fatalf("String() = %q", src.String())
	}
	if src.Stale(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("19 days is not stale")
	}
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	if !src.Stale(now) || src.Age(now) != 48*24*time.Hour {
		t.Fatalf("age %s stale %v", src.Age(now), src.Stale(now))
	}
	if (Source{Origin: OriginTemplates}).Stale(now) {
		t.Fatal("an undated source is never reported stale")
	}
}

func TestRefreshRecordsCatalogVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"catalogVersion":"2026.11.17","vulnerabilities":[{"cveID":"CVE-2021-41773"}]}`))
	}))
	defer srv.Close()
	cache := t.TempDir()
	opts := Options{TemplatesDir: t.TempDir(), Refresh: true, CacheDir: cache, Client: srv.Client(), FeedURL: srv.URL,
		Now: func() time.Time { return time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC) }}
	_, src, err := Resolve(context.Background(), opts)
	if err != nil || src.CatalogVersion != "2026.11.17" || src.AsOf.Day() != 17 {
		t.Fatalf("network: %+v %v", src, err)
	}
	_, cached, err := Resolve(context.Background(), Options{TemplatesDir: t.TempDir(), CacheDir: cache})
	if err != nil || cached.Origin != OriginCache || cached.CatalogVersion != "2026.11.17" {
		t.Fatalf("cache: %+v %v", cached, err)
	}
}
