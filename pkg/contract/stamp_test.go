package contract

import (
	"strings"
	"testing"
)

const stampDoc = `# a hand-written contract: comments and quoting must survive
apiVersion: vulnsuite/v1
kind: Target

metadata:
  id: demo-stamp   # trailing comment
  summary: >-
    a folded
    summary
  verification: unverified  # needs AVX-512 VBMI
  tags: [java, "quoted"]

base:
  kind: image
  image: eclipse-temurin:21-jre
  digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
service:
  ports: [ { container: 8080, protocol: http } ]
requires:
  cpu_flags: [avx512vbmi]
states:
  vulnerable:
    verify:
      - http: { path: /, status: 200 }
`

var stampVO = VerifiedOn{Date: "2026-11-21", Vulnsuite: "v0.4.0", Host: "linux/amd64",
	CPUFlags: []string{"avx512vbmi"}, States: []string{"vulnerable"}}

func TestStampInsertsAndMarksVerified(t *testing.T) {
	out, err := Stamp([]byte(stampDoc), stampVO)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(stampDoc, "  verification: unverified  # needs AVX-512 VBMI\n  tags: [java, \"quoted\"]\n",
		"  verification: verified\n  tags: [java, \"quoted\"]\n"+
			"  verified_on:\n    date: \"2026-11-21\"\n    vulnsuite: v0.4.0\n    host: linux/amd64\n"+
			"    cpu_flags: [avx512vbmi]\n    states: [vulnerable]\n", 1)
	if string(out) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestStampReplacesExistingEvidence(t *testing.T) {
	doc := strings.Replace(stampDoc, "  tags: [java, \"quoted\"]\n", "  verified_on:\n    date: \"2025-01-01\"\n"+
		"    vulnsuite: v0.1.0\n    # old run\n    host: linux/arm64\n    states: [vulnerable]\n\n  tags: [java]\n", 1)
	vo := stampVO
	vo.Platform = "linux/amd64"
	vo.Host = "linux/arm64"
	vo.Vulnsuite = "0.5.0-dev+dirty"
	out, err := Stamp([]byte(doc), vo)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"  verified_on:\n    date: \"2026-11-21\"\n    vulnsuite: \"0.5.0-dev+dirty\"\n" +
		"    host: linux/arm64\n    platform: linux/amd64\n    cpu_flags: [avx512vbmi]\n    states: [vulnerable]\n\n  tags: [java]\n"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "2025-01-01") || strings.Contains(s, "old run") {
		t.Fatalf("old evidence left behind:\n%s", s)
	}
	c, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if c.Metadata.VerifiedOn.Vulnsuite != vo.Vulnsuite || c.IsUnverified() {
		t.Fatalf("parsed back %+v", c.Metadata)
	}
}

func TestStampKeepsCRLF(t *testing.T) {
	doc := strings.ReplaceAll(stampDoc, "\n", "\r\n")
	out, err := Stamp([]byte(doc), stampVO)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(out), "\n") != strings.Count(string(out), "\r\n") {
		t.Fatal("mixed line endings")
	}
}

func TestStampRefusesFlowMetadata(t *testing.T) {
	doc := `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: demo-stamp, summary: x }
base: { kind: image, image: nginx:1 }
service: { ports: [ { container: 80, protocol: http } ] }
states:
  vulnerable: { verify: [ { http: { path: /, status: 200 } } ] }
`
	if _, err := Stamp([]byte(doc), stampVO); err == nil || !strings.Contains(err.Error(), "block mapping") {
		t.Fatalf("want a block-mapping error, got %v", err)
	}
}

func TestStampRejectsBadEvidence(t *testing.T) {
	vo := stampVO
	vo.States = nil
	if _, err := Stamp([]byte(stampDoc), vo); err == nil {
		t.Fatal("want an error for empty states")
	}
}
