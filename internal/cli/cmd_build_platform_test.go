package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// withRequires copies the fixture templates to a temp root and appends a
// requires block to the named template folders.
func withRequires(t *testing.T, reqs map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "templates")
	if err := os.CopyFS(root, os.DirFS(fixtures(t))); err != nil {
		t.Fatal(err)
	}
	for rel, req := range reqs {
		p := filepath.Join(root, filepath.FromSlash(rel), "contract.yaml")
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, append(data, []byte("\nrequires:\n"+req+"\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// Issue #41 item 3: the emulation platform is per job. A target needing
// emulation must not drag the rest of the batch along, and two targets needing
// different emulated arches each get their own.
func TestBuildPlatformIsPerJob(t *testing.T) {
	root := withRequires(t, map[string]string{
		"iot/iot-camera-auth-bypass":    "  arch: [arm64]",
		"exposures/exposed-dotenv-file": "  arch: [s390x]",
	})
	for i := 0; i < 3; i++ { // map-order independence
		fe := enginetest.New() // linux/amd64 host
		code, out, errOut := run(t, fe, "-T", root, "build", "-t", "iot", "-t", "apache", "-t", "exposed-dotenv-file", "-state", "vulnerable")
		if code != ExitOK {
			t.Fatalf("build: %d\n%s\n%s", code, out, errOut)
		}
		got := map[string]string{}
		for _, b := range fe.Builds {
			got[strings.SplitN(strings.TrimPrefix(b.Tags[0], "vulnsuite/"), ":", 2)[0]] = b.Platform
		}
		want := map[string]string{
			"iot-camera-auth-bypass":             "linux/arm64",
			"apache-httpd-2.4.49-cve-2021-41773": "",
			"exposed-dotenv-file":                "linux/s390x",
		}
		for id, p := range want {
			if pf, ok := got[id]; !ok || pf != p {
				t.Fatalf("%s built for %q (present=%v), want %q; all: %v\n%s", id, pf, ok, p, got, out)
			}
		}
		if !strings.Contains(out, "building iot-camera-auth-bypass under emulation for linux/arm64") ||
			!strings.Contains(out, "building exposed-dotenv-file under emulation for linux/s390x") {
			t.Fatalf("emulation not announced per target:\n%s", out)
		}
	}
	// An explicit -platform applies to every job.
	fe := enginetest.New()
	code, out, errOut := run(t, fe, "-T", root, "build", "-t", "iot", "-t", "apache", "-state", "vulnerable", "-platform", "linux/arm/v7")
	if code != ExitOK {
		t.Fatalf("build -platform: %d\n%s\n%s", code, out, errOut)
	}
	for _, b := range fe.Builds {
		if b.Platform != "linux/arm/v7" {
			t.Fatalf("%v built for %q, want the explicit linux/arm/v7", b.Tags, b.Platform)
		}
	}
}
