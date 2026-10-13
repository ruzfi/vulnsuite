package loader

import (
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
	if err != nil || len(paths) != 5 {
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
	// ambiguous substring
	if _, err := s.Find("e"); err == nil {
		t.Fatal("expected ambiguity error")
	}
	if _, err := s.Find("does-not-exist"); err == nil {
		t.Fatal("expected not-found error")
	}
	many, err := s.FindMany([]string{"iot", "iot-camera-auth-bypass", "grafana"}, false)
	if err != nil || len(many) != 2 {
		t.Fatalf("FindMany dedup: %v %v", err, many)
	}
	byID, err := s.ByID()
	if err != nil || len(byID) != 5 {
		t.Fatalf("ByID: %v %d", err, len(byID))
	}
}
