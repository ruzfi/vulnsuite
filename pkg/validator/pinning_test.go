package validator

import (
	"strings"
	"testing"
)

const pinHead = `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: pin-demo, summary: x, vuln_refs: [VS-X], references: [https://e.invalid] }
service:
  ports: [ { container: 80, protocol: http } ]
  healthcheck: { tcp: { port: 80 }, timeout: 10s }
`

const pinned = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func findingsFor(fs []Finding, rule string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

// Issue #41 item 2: state image overrides and sidecar images must be pinned,
// with the same -allow-unpinned downgrade as the base.
func TestPinningStateImagesAndSidecars(t *testing.T) {
	doc := pinHead + `  sidecars:
    - { name: db, image: mysql:5.7 }
    - { name: cache, image: redis:7, digest: ` + pinned + ` }
    - { name: inline, image: "redis@` + pinned + `" }
base: { kind: image, image: httpd:2.4.50, digest: ` + pinned + ` }
states:
  vulnerable:
    sidecars: { cache: { image: redis:6 } }
  patched:
    image: httpd:2.4.51
    sidecars: { cache: { image: redis:7.2, digest: ` + pinned + ` } }
`
	c := parse(t, doc)
	strict := (&Validator{}).Check(c)
	st := findingsFor(strict, "unpinned-state-image")
	if len(st) != 1 || st[0].Level != Error || !strings.Contains(st[0].Message, "states.patched.image httpd:2.4.51") {
		t.Fatalf("unpinned-state-image: %v", st)
	}
	sc := findingsFor(strict, "unpinned-sidecar")
	if len(sc) != 2 {
		t.Fatalf("want 2 unpinned-sidecar (db, vulnerable cache override), got %v", sc)
	}
	var msgs []string
	for _, f := range sc {
		if f.Level != Error {
			t.Fatalf("unpinned sidecar must be an error by default: %s", f)
		}
		msgs = append(msgs, f.Message)
	}
	all := strings.Join(msgs, "\n")
	if !strings.Contains(all, "sidecar db image mysql:5.7") || !strings.Contains(all, "states.vulnerable.sidecars.cache image redis:6") {
		t.Fatalf("messages:\n%s", all)
	}
	if len(findingsFor(strict, "unpinned-base")) != 0 {
		t.Fatal("base is pinned")
	}
	// -allow-unpinned downgrades them, exactly like unpinned-base.
	for _, f := range (&Validator{AllowUnpinned: true}).Check(c) {
		if (f.Rule == "unpinned-state-image" || f.Rule == "unpinned-sidecar") && f.Level != Warning {
			t.Fatalf("-allow-unpinned must downgrade %s", f)
		}
	}
}

// Issue #41 item 2: a source base pins a full commit id; a branch or tag is
// unpinned, an abbreviated SHA a warning.
func TestPinningSourceCommit(t *testing.T) {
	mk := func(commit string) []Finding {
		doc := pinHead + "base: { kind: source, repo: https://example.invalid/x.git, commit: \"" + commit + "\" }\n" +
			"states:\n  vulnerable: {}\n"
		return (&Validator{}).Check(parse(t, doc))
	}
	for _, full := range []string{
		"0123456789abcdef0123456789abcdef01234567",
		"0123456789ABCDEF0123456789ABCDEF01234567",
		strings.Repeat("ab", 32), // SHA-256
	} {
		fs := mk(full)
		if len(findingsFor(fs, "unpinned-base"))+len(findingsFor(fs, "short-commit")) != 0 {
			t.Fatalf("full sha %s flagged: %v", full, fs)
		}
	}
	short := findingsFor(mk("0123abc"), "short-commit")
	if len(short) != 1 || short[0].Level != Warning {
		t.Fatalf("short sha: %v", short)
	}
	for _, ref := range []string{"main", "v1.2.3", "0123456789abcdef0123456789abcdef0123456789"} {
		fs := findingsFor(mk(ref), "unpinned-base")
		if len(fs) != 1 || fs[0].Level != Error {
			t.Fatalf("commit %q must be unpinned-base: %v", ref, fs)
		}
	}
	// -allow-unpinned downgrades a branch commit like any unpinned base.
	doc := pinHead + "base: { kind: source, repo: https://example.invalid/x.git, commit: main }\nstates:\n  vulnerable: {}\n"
	if fs := findingsFor((&Validator{AllowUnpinned: true}).Check(parse(t, doc)), "unpinned-base"); len(fs) != 1 || fs[0].Level != Warning {
		t.Fatalf("-allow-unpinned: %v", fs)
	}
}

// Issue #152 item 6: an inline digest must be a full sha256 digest to pin, and
// one that differs from the digest field (which wins) is an error.
func TestPinningInlineDigest(t *testing.T) {
	other := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, tc := range []struct {
		image, digest string
		unpinned      bool
		conflict      bool
	}{
		{image: "httpd@" + pinned},
		{image: "httpd", digest: pinned},
		{image: "httpd@" + pinned, digest: pinned},
		{image: "httpd@sha256:", unpinned: true},
		{image: "httpd@sha256:zzz", unpinned: true},
		{image: "httpd@" + strings.ToUpper(pinned[7:]), unpinned: true},
		{image: "httpd@" + other, digest: pinned, conflict: true},
	} {
		base := "base: { kind: image, image: \"" + tc.image + "\""
		if tc.digest != "" {
			base += ", digest: " + tc.digest
		}
		doc := pinHead + base + " }\nstates:\n  vulnerable:\n    sidecars: {}\n"
		fs := (&Validator{}).Check(parse(t, doc))
		if got := len(findingsFor(fs, "unpinned-base")) > 0; got != tc.unpinned {
			t.Errorf("%s/%s: unpinned-base = %v, want %v", tc.image, tc.digest, got, tc.unpinned)
		}
		cf := findingsFor(fs, "digest-conflict")
		if (len(cf) > 0) != tc.conflict || (tc.conflict && cf[0].Level != Error) {
			t.Errorf("%s/%s: digest-conflict = %v, want %v", tc.image, tc.digest, cf, tc.conflict)
		}
	}
	doc := pinHead + `  sidecars:
    - { name: cache, image: "redis@` + other + `", digest: ` + pinned + ` }
base: { kind: image, image: httpd, digest: ` + pinned + ` }
states:
  vulnerable:
    image: "httpd@` + other + `"
    digest: ` + pinned + `
    sidecars: { cache: { image: "redis@` + other + `", digest: ` + pinned + ` } }
`
	if cf := findingsFor((&Validator{}).Check(parse(t, doc)), "digest-conflict"); len(cf) != 3 {
		t.Errorf("want 3 digest-conflict (state, override, sidecar), got %v", cf)
	}
}
