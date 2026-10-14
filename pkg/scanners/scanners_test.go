package scanners

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

func fakeCheckout(t *testing.T) *Index {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	write("http/cves/2021/CVE-2021-41773.yaml", "id: CVE-2021-41773\ninfo:\n  name: Apache traversal\n  severity: high\n  tags: cve,cve2021,apache\n  classification:\n    cve-id: CVE-2021-41773\n")
	write("http/exposures/laravel-env.yaml", "id: laravel-env\ninfo:\n  name: Laravel .env\n  severity: high\n")
	write("http/misc/combo.yaml", "id: apache-combo\ninfo:\n  name: combo\n  classification:\n    cve-id:\n      - CVE-2021-41773\n      - CVE-2021-42013\n")
	write("README.md", "CVE-2000-0001 in prose does not count")
	write(".hidden/skip.yaml", "id: hidden\n")
	idx, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func TestIndexAndRefs(t *testing.T) {
	idx := fakeCheckout(t)
	if idx.Count != 3 || len(idx.ByCVE["CVE-2021-41773"]) != 2 || idx.ByCVE["CVE-2021-42013"][0].ID != "apache-combo" {
		t.Fatalf("%+v", idx)
	}
	if idx.ByID["laravel-env"].Path != "http/exposures/laravel-env.yaml" {
		t.Fatal(idx.ByID["laravel-env"])
	}
	if r := ParseRef("nuclei:x"); r.Scanner != "nuclei" || r.ID != "x" {
		t.Fatal(r)
	}
	if r := ParseRef("CVE-2021-41773"); r.Scanner != "nuclei" || r.ID != "CVE-2021-41773" {
		t.Fatal("bare id defaults to nuclei")
	}
	if r := ParseRef("Mercury:ATB-1"); r.Scanner != "mercury" {
		t.Fatal(r)
	}
}

func contractWith(detection string, detectedBy, refs []string) *contract.Contract {
	return &contract.Contract{Metadata: contract.Metadata{ID: "t", Detection: detection, DetectedBy: detectedBy, VulnRefs: refs}, SourcePath: "/x/t/contract.yaml"}
}

func TestMatch(t *testing.T) {
	idx := fakeCheckout(t)
	// declared + verified, resolved to a file
	r := Match(contractWith("scanner", []string{"nuclei:laravel-env"}, nil), idx)
	if len(r.Declared) != 1 || !r.Declared[0].Verified || r.Declared[0].Template == nil || r.Declared[0].Missing {
		t.Fatalf("%+v", r)
	}
	if lines := strings.Join(r.Lines(contractWith("scanner", nil, nil)), "\n"); !strings.Contains(lines, "verified") || strings.Contains(lines, "not yet verified") {
		t.Fatal(lines)
	}
	// declared but unknown id, plus a CVE suggestion
	r = Match(contractWith("", []string{"nuclei:nope"}, []string{"CVE-2021-41773"}), idx)
	if !r.Declared[0].Missing || len(r.Suggested) != 2 {
		t.Fatalf("%+v", r)
	}
	lines := strings.Join(r.Lines(contractWith("", nil, nil)), "\n")
	for _, want := range []string{"not found in the local", "not yet verified", "also matching", "nuclei:apache-combo"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("missing %q in\n%s", want, lines)
		}
	}
	// nothing declared, CVE has templates -> suggest
	r = Match(contractWith("", nil, []string{"cve-2021-42013"}), idx)
	if len(r.Suggested) != 1 || r.Covered() {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(strings.Join(r.Lines(contractWith("", nil, nil)), "\n"), "add it to detected_by") {
		t.Fatal("expected the add-it hint")
	}
	// custom-only
	lines = strings.Join(Match(contractWith("custom-only", nil, nil), idx).Lines(contractWith("custom-only", nil, nil)), "\n")
	if !strings.Contains(lines, "custom-only") || !strings.Contains(lines, UpstreamURL) {
		t.Fatal(lines)
	}
	// a real gap: CVE, nothing anywhere
	c := contractWith("", nil, []string{"CVE-2018-15473"})
	lines = strings.Join(Match(c, idx).Lines(c), "\n")
	if !strings.Contains(lines, "detection gap") || !strings.Contains(lines, "has none for CVE-2018-15473") || !strings.Contains(lines, "t/contract.yaml") {
		t.Fatal(lines)
	}
	// no checkout at all
	lines = strings.Join(Match(c, nil).Lines(c), "\n")
	if !strings.Contains(lines, "-nuclei-templates DIR") {
		t.Fatal(lines)
	}
}

func TestResolveDir(t *testing.T) {
	dir := t.TempDir()
	if ResolveDir(dir) != dir {
		t.Fatal("explicit dir")
	}
	t.Setenv(Env, dir)
	if ResolveDir("") != dir {
		t.Fatal("env dir")
	}
	t.Setenv(Env, filepath.Join(dir, "missing"))
	t.Setenv("HOME", dir)
	if ResolveDir("") != "" {
		t.Fatal("expected none")
	}
}

func TestParseRefScannersAndKnown(t *testing.T) {
	cases := []struct {
		in      string
		scanner string
		id      string
		known   bool
	}{
		{"nuclei:CVE-2021-41773", "nuclei", "CVE-2021-41773", true},
		{"nmap:http-aspnet-debug", "nmap", "http-aspnet-debug", true},
		{"laravel-env", "nuclei", "laravel-env", true}, // bare id defaults to nuclei
		{"NMAP:Foo", "nmap", "Foo", true},              // scanner lowercased
		{"bogus:x", "bogus", "x", false},
	}
	for _, c := range cases {
		r := ParseRef(c.in)
		if r.Scanner != c.scanner || r.ID != c.id {
			t.Errorf("ParseRef(%q) = %+v, want %s:%s", c.in, r, c.scanner, c.id)
		}
		if r.Known() != c.known {
			t.Errorf("ParseRef(%q).Known() = %v, want %v", c.in, r.Known(), c.known)
		}
	}
}
