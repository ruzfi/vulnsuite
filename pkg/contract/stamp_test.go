package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	vo.Host = "linux/arm64" // the host of the old run, so it is replaced
	vo.Vulnsuite = "0.5.0-dev+dirty"
	out, err := Stamp([]byte(doc), vo)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"  verified_on:\n    date: \"2026-11-21\"\n    vulnsuite: \"0.5.0-dev+dirty\"\n" +
		"    host: linux/arm64\n    cpu_flags: [avx512vbmi]\n    states: [vulnerable]\n\n  tags: [java]\n"} {
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
	if c.Metadata.VerifiedOn[0].Vulnsuite != vo.Vulnsuite || c.IsUnverified() {
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

// A run on another host is added next to the recorded one, as a list; a later
// run on either host replaces only that host's entry.
func TestStampKeepsRunsOnOtherHosts(t *testing.T) {
	arm := stampVO
	arm.Host, arm.Date, arm.CPUFlags = "linux/arm64", "2026-10-02", nil
	once, err := Stamp([]byte(stampDoc), arm)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(once), "  verified_on:\n    date: \"2026-10-02\"\n") {
		t.Fatalf("a single run must stay a mapping (the form v0.5.0 reads):\n%s", once)
	}
	twice, err := Stamp(once, stampVO)
	if err != nil {
		t.Fatal(err)
	}
	want := "  verified_on:\n" +
		"    - date: \"2026-10-02\"\n      vulnsuite: v0.4.0\n      host: linux/arm64\n      states: [vulnerable]\n" +
		"    - date: \"2026-11-21\"\n      vulnsuite: v0.4.0\n      host: linux/amd64\n      cpu_flags: [avx512vbmi]\n      states: [vulnerable]\n"
	if !strings.Contains(string(twice), want) {
		t.Fatalf("want both runs:\n%s", twice)
	}
	// Emulated amd64 on an arm64 host is a different run from native arm64.
	emu := arm
	emu.Platform, emu.Date = "linux/amd64", "2026-11-22"
	thrice, err := Stamp(twice, emu)
	if err != nil {
		t.Fatal(err)
	}
	// A fresh arm64 run replaces the old one in place and keeps the others.
	arm.Date, arm.Vulnsuite = "2026-12-01", "v0.6.0"
	out, err := Stamp(thrice, arm)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range c.Metadata.VerifiedOn {
		got = append(got, r.Date+" "+r.RanOn())
	}
	if strings.Join(got, ", ") != "2026-12-01 linux/arm64, 2026-11-21 linux/amd64, 2026-11-22 linux/arm64 running linux/amd64" {
		t.Fatalf("runs: %v\n%s", got, out)
	}
	if l := c.Metadata.VerifiedOn.Latest(); l == nil || l.Date != "2026-12-01" {
		t.Fatalf("Latest = %+v", l)
	}
	if strings.Contains(string(out), "2026-10-02") {
		t.Fatalf("the replaced run is still there:\n%s", out)
	}
}

// A list written at the key's own indentation (also valid YAML) is replaced
// whole, not left dangling after the new block.
func TestStampReplacesListAtKeyIndent(t *testing.T) {
	doc := strings.Replace(stampDoc, "  tags: [java, \"quoted\"]\n", "  verified_on:\n"+
		"  - date: \"2025-01-01\"\n    vulnsuite: v0.1.0\n    host: linux/arm64\n    states: [vulnerable]\n"+
		"  - date: \"2025-02-01\"\n    vulnsuite: v0.1.0\n    host: linux/amd64\n    states: [vulnerable]\n"+
		"  tags: [java]\n", 1)
	if _, err := Parse([]byte(doc)); err != nil {
		t.Fatal(err)
	}
	out, err := Stamp([]byte(doc), stampVO)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if r := c.Metadata.VerifiedOn; len(r) != 2 || r[0].Date != "2025-01-01" || r[1].Date != "2026-11-21" ||
		!strings.Contains(string(out), "  tags: [java]\n") {
		t.Fatalf("runs %+v:\n%s", r, out)
	}
}

func TestVerifiedRunsJSONMirrorsContract(t *testing.T) {
	one, _ := json.Marshal(VerifiedRuns{stampVO})
	if !strings.HasPrefix(string(one), `{"date":`) {
		t.Fatalf("one run must be an object: %s", one)
	}
	two, _ := json.Marshal(VerifiedRuns{stampVO, stampVO})
	if !strings.HasPrefix(string(two), `[{"date":`) {
		t.Fatalf("several runs must be an array: %s", two)
	}
}

// #137: verification written after verified_on is rewritten too.
func TestStampVerificationAfterVerifiedOn(t *testing.T) {
	doc := strings.Replace(stampDoc, "  verification: unverified  # needs AVX-512 VBMI\n  tags: [java, \"quoted\"]\n",
		"  tags: [java, \"quoted\"]\n  verified_on:\n    date: \"2025-01-01\"\n    vulnsuite: v0.1.0\n    host: linux/arm64\n"+
			"    states: [vulnerable]\n  verification: unverified\n", 1)
	out, err := Stamp([]byte(doc), stampVO)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsUnverified() || len(c.Metadata.VerifiedOn) != 2 {
		t.Fatalf("got:\n%s", out)
	}
}

func writeContract(t *testing.T, dir, doc string) string {
	t.Helper()
	p := filepath.Join(dir, "contract.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// #137: StampSource refuses a file whose contract changed since it was
// loaded, but not one where only the evidence changed (another stamp).
func TestStampSourceChecksTheFile(t *testing.T) {
	dir := t.TempDir()
	p := writeContract(t, dir, stampDoc)
	loaded := &Contract{SourcePath: p, SourceData: []byte(stampDoc)}

	other := stampVO
	other.Host = "linux/arm64"
	if err := StampFile(p, other); err != nil { // a concurrent stamp on another host
		t.Fatal(err)
	}
	if err := StampSource(loaded, stampVO); err != nil {
		t.Fatalf("evidence-only change refused: %v", err)
	}
	data, _ := os.ReadFile(p)
	c, err := Parse(data)
	if err != nil || len(c.Metadata.VerifiedOn) != 2 {
		t.Fatalf("lost a run: %v\n%s", err, data)
	}

	writeContract(t, dir, strings.Replace(stampDoc, "status: 200", "status: 302", 1))
	err = StampSource(loaded, stampVO)
	if err == nil || !strings.Contains(err.Error(), "the contract changed since it was loaded") {
		t.Fatalf("changed probe: %v", err)
	}
}

// #137: a symlinked contract is stamped through the link, which stays a link.
func TestStampFileThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	real := writeContract(t, dir, stampDoc)
	link := filepath.Join(t.TempDir(), "contract.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := StampFile(link, stampVO); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v %v", fi, err)
	}
	if data, _ := os.ReadFile(real); !strings.Contains(string(data), "verified_on:") {
		t.Fatalf("the target was not stamped:\n%s", data)
	}
}

// #137: a stamp waits for another one writing the same file, and takes over
// a lock left by one that died.
func TestStampLock(t *testing.T) {
	w, s := stampLockWait, stampLockStale
	t.Cleanup(func() { stampLockWait, stampLockStale = w, s })
	stampLockWait = 200 * time.Millisecond
	dir := t.TempDir()
	p := writeContract(t, dir, stampDoc)
	lock := filepath.Join(dir, ".contract.yaml.stamp-lock")
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := StampFile(p, stampVO); err == nil || !strings.Contains(err.Error(), "another stamp is writing this file") {
		t.Fatalf("held lock: %v", err)
	}
	old := time.Now().Add(-2 * time.Minute)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	if err := StampFile(p, stampVO); err != nil {
		t.Fatalf("stale lock: %v", err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Errorf("lock left behind: %v", err)
	}
}
