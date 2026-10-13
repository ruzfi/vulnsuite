// Package e2e exercises the real engine end to end: build a local-kind
// template from scratch (no registry needed), run it in host and internal
// exposure, verify both states, build an overlay on top of it, tear down.
//
// It runs only when VULNSUITE_E2E=1 and a Docker daemon is reachable.
package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/engines"
	"github.com/ruzfi/vulnsuite/pkg/loader"
	"github.com/ruzfi/vulnsuite/pkg/runner"
	"github.com/ruzfi/vulnsuite/pkg/validator"
)

const serverSrc = `package main

import (
	"net/http"
	"os"
)

func main() {
	mode := os.Getenv("MODE")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	http.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		if mode == "patched" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("APP_KEY=x\nDB_PASSWORD=s3cret\n"))
	})
	http.HandleFunc("/banner", func(w http.ResponseWriter, r *http.Request) {
		b, _ := os.ReadFile("/etc/banner")
		w.Write(b)
	})
	http.ListenAndServe(":8080", nil)
}
`

const localContract = `apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: e2e-static-http
  summary: e2e fixture, a static Go server serving its .env
  vuln_refs: [VS-E2E-DOTENV]
  severity: high
  references: [https://example.invalid]
  detection: custom-only
base:
  kind: build
  context: src
service:
  ports: [ { container: 8080, protocol: http } ]
  healthcheck: { http: { path: /, status: 200 }, timeout: 30s }
states:
  vulnerable:
    verify:
      - http: { path: /.env, status: 200, body_matches: "DB_PASSWORD=" }
  patched:
    environment: { MODE: patched }
    verify:
      - http: { path: /.env, status_in: [404], body_absent: "DB_PASSWORD" }
`

const overlayContract = `apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: e2e-overlay-banner
  summary: e2e fixture, overlay a banner file onto a prebuilt image
  vuln_refs: [VS-E2E-BANNER]
  severity: low
  references: [https://example.invalid]
base:
  kind: image
  image: IMAGE
service:
  ports: [ { container: 8080, protocol: http } ]
  healthcheck: { http: { path: /, status: 200 }, timeout: 30s }
states:
  vulnerable:
    overlay: [ { src: files/vuln.txt, dest: /etc/banner } ]
    verify:
      - http: { path: /banner, status: 200, body_matches: "VULNERABLE-BANNER" }
  patched:
    overlay: [ { src: files/fixed.txt, dest: /etc/banner } ]
    verify:
      - http: { path: /banner, status: 200, body_absent: "VULNERABLE-BANNER" }
`

func TestEndToEnd(t *testing.T) {
	if os.Getenv("VULNSUITE_E2E") == "" {
		t.Skip("set VULNSUITE_E2E=1 to run against a Docker daemon")
	}
	for _, kind := range []string{"sdk", "api"} {
		t.Run(kind, func(t *testing.T) { endToEnd(t, kind) })
	}
}

func endToEnd(t *testing.T, kind string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	eng, err := engines.New(kind, "")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := eng.Ping(ctx); err != nil {
		t.Skipf("no daemon: %v", err)
	} else {
		t.Logf("daemon %s", v)
	}

	root := t.TempDir()
	// -- local-kind template with a static binary, FROM scratch.
	tplDir := filepath.Join(root, "fixtures", "e2e-static-http")
	src := filepath.Join(tplDir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(filepath.Join(src, "main.go"), []byte(serverSrc), 0o644))
	build := exec.Command("go", "build", "-o", filepath.Join(src, "server"), "./main.go")
	build.Dir = src
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH, "GOFLAGS=-mod=mod", "GO111MODULE=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v\n%s", err, out)
	}
	os.Remove(filepath.Join(src, "main.go"))
	must(t, os.WriteFile(filepath.Join(src, "Dockerfile"), []byte("FROM scratch\nCOPY server /server\nEXPOSE 8080\nENTRYPOINT [\"/server\"]\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(tplDir, "contract.yaml"), []byte(localContract), 0o644))

	store := loader.New(root)
	c, err := store.LoadSelector("e2e-static-http")
	if err != nil {
		t.Fatal(err)
	}
	if f := (&validator.Validator{}).Check(c); validator.Worst(f) == validator.Error {
		t.Fatalf("fixture does not validate: %v", f)
	}

	b := builder.New(eng)
	outcomes := b.ResolveAll(ctx, []builder.Job{{Contract: c, State: "vulnerable"}, {Contract: c, State: "patched"}}, 2, builder.Options{Pull: false}, nil)
	for _, o := range outcomes {
		if o.Err != nil {
			t.Fatalf("build %s: %v\n%s", o.Job.State, o.Err, o.Log)
		}
		if !o.Resolved.Built {
			t.Errorf("%s: expected a fresh build", o.Job.State)
		}
		t.Logf("built %s -> %s in %s", o.Job.State, o.Resolved.Ref, o.Resolved.Elapsed)
	}
	// Second resolve must reuse (content-addressed).
	again, err := b.Resolve(ctx, c, "vulnerable", builder.Options{})
	if err != nil || again.Built {
		t.Fatalf("expected reuse, got built=%v err=%v", again != nil && again.Built, err)
	}
	t.Cleanup(func() {
		for _, s := range contract.StateNames {
			_ = eng.ImageRemove(context.Background(), c.ImageTag(s), true)
		}
	})

	r := runner.New(eng)
	t.Cleanup(func() { _, _ = r.StopAll(context.Background(), "") })

	// -- host exposure: verify from this process.
	for _, state := range []string{"vulnerable", "patched"} {
		exp := runner.Exposure{Mode: runner.ModeHost, Bind: "127.0.0.1"}
		h, err := r.Run(ctx, c, state, exp, runner.Options{Verify: true})
		if err != nil {
			t.Fatalf("run %s: %v", state, err)
		}
		if !h.Ready {
			logs, _ := eng.ContainerLogs(ctx, h.Container, 20)
			t.Fatalf("%s not ready; logs:\n%s", state, logs)
		}
		if h.VerifyOK == nil || !*h.VerifyOK {
			t.Fatalf("%s verify failed: %s", state, h.VerifyDetail)
		}
		t.Logf("%s ok at %s: %s", state, h.ScannerTarget(), strings.ReplaceAll(h.VerifyDetail, "\n", " | "))
		r.Stop(ctx, h)
	}

	// -- internal exposure: runs, is listed, has an ip, stop removes it.
	h, err := r.Run(ctx, c, "vulnerable", runner.DefaultExposure(), runner.Options{Verify: true})
	if err != nil {
		t.Fatalf("internal run: %v", err)
	}
	t.Logf("internal: ip=%q ready=%v verify=%v detail=%s", h.IP, h.Ready, h.VerifyOK, strings.ReplaceAll(h.VerifyDetail, "\n", " | "))
	rows, err := r.Running(ctx, runner.DefaultNetwork)
	if err != nil || len(rows) != 1 || rows[0].ID != c.ID() {
		t.Fatalf("ps: %v %+v", err, rows)
	}
	removed, err := r.StopAll(ctx, c.ID())
	if err != nil || len(removed) != 1 {
		t.Fatalf("stop: %v %v", err, removed)
	}

	// -- overlay on top of the image we just built (no registry involved).
	ovDir := filepath.Join(root, "fixtures", "e2e-overlay-banner")
	must(t, os.MkdirAll(filepath.Join(ovDir, "files"), 0o755))
	must(t, os.WriteFile(filepath.Join(ovDir, "files", "vuln.txt"), []byte("VULNERABLE-BANNER\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(ovDir, "files", "fixed.txt"), []byte("all good\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(ovDir, "contract.yaml"),
		[]byte(strings.Replace(overlayContract, "IMAGE", c.ImageTag("vulnerable"), 1)), 0o644))
	oc, err := store.LoadSelector("e2e-overlay-banner")
	if err != nil {
		t.Fatal(err)
	}
	if oc.BuildKind("vulnerable") != contract.BuildKindOverlay {
		t.Fatalf("expected overlay kind, got %s", oc.BuildKind("vulnerable"))
	}
	t.Cleanup(func() {
		for _, s := range contract.StateNames {
			_ = eng.ImageRemove(context.Background(), oc.ImageTag(s), true)
		}
	})
	for _, state := range []string{"vulnerable", "patched"} {
		h, err := r.Run(ctx, oc, state, runner.Exposure{Mode: runner.ModeHost, Bind: "127.0.0.1"}, runner.Options{Verify: true, Build: builder.Options{Pull: false}})
		if err != nil {
			t.Fatalf("overlay run %s: %v", state, err)
		}
		if h.VerifyOK == nil || !*h.VerifyOK {
			t.Fatalf("overlay %s verify failed: %s", state, h.VerifyDetail)
		}
		t.Logf("overlay %s ok: %s", state, h.VerifyDetail)
		r.Stop(ctx, h)
	}

	// -- exec probe through the engine.
	code, out, err := eng.ContainerExec(ctx, "no-such-container", "true", 5*time.Second)
	if err == nil {
		t.Fatalf("exec on a missing container should fail, got %d %q", code, out)
	}
	imgs, err := eng.ImageList(ctx, contract.ImageRepoPrefix+"/")
	if err != nil || len(imgs) < 4 {
		t.Fatalf("image list: %v %v", err, imgs)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
