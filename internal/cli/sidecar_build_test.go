package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

const sidecarBuildContract = `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: cli-sidecar-build, summary: a target with a built driver sidecar, vuln_refs: [VS-CLI-1] }
base: { kind: build, context: src }
service:
  ports: [ { container: 80, protocol: http } ]
  sidecars:
    - { name: driver, build: { context: sidecars/driver }, command: [sleep, infinity] }
states:
  vulnerable:
    verify: [ { http: { path: /, status: 200, body_matches: vuln } } ]
  patched:
    overlay: [ { src: files/fixed, dest: fixed } ]
    verify: [ { http: { path: /, status: 200, body_matches: fixed } } ]
`

func sidecarBuildTemplates(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "templates")
	dir := filepath.Join(root, "demo", "cli-sidecar-build")
	files := map[string]string{
		"contract.yaml":              sidecarBuildContract,
		"src/Dockerfile":             "FROM busybox\n",
		"files/fixed":                "fixed\n",
		"sidecars/driver/Dockerfile": "FROM busybox\nCOPY drive.sh /drive.sh\n",
		"sidecars/driver/drive.sh":   "#!/bin/sh\n",
	}
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// build builds a built sidecar once for both states, reports it under each,
// and -push pushes it once next to the state images.
func TestBuildBuildsAndPushesSidecar(t *testing.T) {
	root := sidecarBuildTemplates(t)
	fe := enginetest.New()
	code, out, errOut := run(t, fe, "-T", root, "-json", "build", "-t", "cli-sidecar-build", "-j", "2", "-push", "-registry", "reg.example/vs")
	if code != ExitOK {
		t.Fatalf("build: %d\n%s\n%s", code, out, errOut)
	}
	var results []buildResult
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(results) != 2 {
		t.Fatalf("results %+v", results)
	}
	var tag string
	built := 0
	for _, r := range results {
		if len(r.Sidecars) != 1 || r.Sidecars[0].Name != "driver" || !strings.HasPrefix(r.Sidecars[0].Ref, "vulnsuite/cli-sidecar-build:sidecar-driver-") {
			t.Fatalf("%s: sidecars %+v", r.State, r.Sidecars)
		}
		if tag != "" && r.Sidecars[0].Ref != tag {
			t.Fatalf("the states must share the sidecar image: %s vs %s", tag, r.Sidecars[0].Ref)
		}
		tag = r.Sidecars[0].Ref
		if r.Sidecars[0].Built {
			built++
		}
	}
	if built != 1 {
		t.Fatalf("sidecar built %d times", built)
	}
	hash := tag[strings.LastIndex(tag, "-")+1:]
	sidecarPushes := 0
	for _, p := range fe.Pushes {
		if strings.Contains(p, ":sidecar-") {
			sidecarPushes++
			if p != "reg.example/vs/cli-sidecar-build:sidecar-driver" && p != "reg.example/vs/cli-sidecar-build:sidecar-driver-"+hash {
				t.Errorf("unexpected sidecar push %s", p)
			}
		}
	}
	if sidecarPushes != 2 || len(fe.Pushes) != 6 {
		t.Fatalf("pushes %v", fe.Pushes)
	}

	// Text output names the sidecar; a second build reuses everything.
	code, out, errOut = run(t, fe, "-T", root, "build", "-t", "cli-sidecar-build", "-state", "vulnerable")
	if code != ExitOK || !strings.Contains(out, "sidecar driver reused  "+tag) {
		t.Fatalf("rebuild: %d\n%s\n%s", code, out, errOut)
	}
	// validate is clean: a built sidecar is pinned.
	code, out, errOut = run(t, fe, "-T", root, "validate")
	if code != ExitOK || strings.Contains(out+errOut, "unpinned-sidecar") {
		t.Fatalf("validate: %d\n%s\n%s", code, out, errOut)
	}
}
