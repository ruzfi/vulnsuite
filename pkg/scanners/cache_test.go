package scanners

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadCachedReusesAndInvalidates(t *testing.T) {
	root := fakeCheckout(t).Root
	cacheDir := t.TempDir()
	want, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}

	// First call builds the index and writes the cache.
	got, err := LoadCached(root, cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadCached = %+v, want %+v", got, want)
	}
	files, _ := filepath.Glob(filepath.Join(cacheDir, "nuclei-index-*.json"))
	if len(files) != 1 {
		t.Fatalf("cache files: %v", files)
	}

	// Second call is served from the cache: equal to Load, and without
	// parsing (a doctored cache entry shows through).
	if got, err = LoadCached(root, cacheDir); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("cached LoadCached = %+v, %v", got, err)
	}
	data, _ := os.ReadFile(files[0])
	doctored := strings.Replace(string(data), "Laravel .env", "from-cache", 1)
	if doctored == string(data) {
		t.Fatal("cache does not hold the template name")
	}
	os.WriteFile(files[0], []byte(doctored), 0o644)
	if got, _ = LoadCached(root, cacheDir); got.ByID["laravel-env"].Name != "from-cache" {
		t.Fatalf("cache not used: %+v", got.ByID["laravel-env"])
	}

	// Editing a template (size or mtime) invalidates it.
	p := filepath.Join(root, "http", "exposures", "laravel-env.yaml")
	os.WriteFile(p, []byte("id: laravel-env\ninfo:\n  name: Laravel env file\n  severity: high\n"), 0o644)
	if got, _ = LoadCached(root, cacheDir); got.ByID["laravel-env"].Name != "Laravel env file" {
		t.Fatalf("edit not picked up: %+v", got.ByID["laravel-env"])
	}
	later := time.Now().Add(time.Hour)
	os.WriteFile(p, []byte("id: laravel-env\ninfo:\n  name: Laravel env FILE\n  severity: high\n"), 0o644) // same size
	os.Chtimes(p, later, later)
	if got, _ = LoadCached(root, cacheDir); got.ByID["laravel-env"].Name != "Laravel env FILE" {
		t.Fatalf("same-size edit with a new mtime not picked up: %+v", got.ByID["laravel-env"])
	}

	// A new template and a removed one invalidate it.
	os.WriteFile(filepath.Join(root, "http", "new.yaml"), []byte("id: brand-new\ninfo:\n  classification:\n    cve-id: CVE-2024-0001\n"), 0o644)
	os.Remove(filepath.Join(root, "http", "misc", "combo.yaml"))
	got, _ = LoadCached(root, cacheDir)
	want, _ = Load(root)
	if !reflect.DeepEqual(got, want) || got.ByID["brand-new"] == nil || got.ByID["apache-combo"] != nil {
		t.Fatalf("add/remove not picked up: %+v", got)
	}

	// A corrupt cache is rebuilt, not an error.
	os.WriteFile(files[0], []byte("{not json"), 0o644)
	if got, err = LoadCached(root, cacheDir); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("corrupt cache: %+v, %v", got, err)
	}
}

// A cache directory that cannot be written leaves the index intact.
func TestLoadCachedUnwritableCacheDir(t *testing.T) {
	root := fakeCheckout(t).Root
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, []byte("x"), 0o644)
	want, _ := Load(root)
	got, err := LoadCached(root, blocker)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v, %v", got, err)
	}
}
