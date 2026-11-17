package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/engines"
	"github.com/ruzfi/vulnsuite/pkg/runner"
)

// foreignArch picks an architecture other than the host's, with a busybox
// image published only for it, and what `uname -m` prints there.
func foreignArch(host string) (arch, image, uname string) {
	if host == "amd64" {
		return "arm64", "arm64v8/busybox:1.36.1", "aarch64"
	}
	return "amd64", "amd64/busybox:1.36.1", "x86_64"
}

func daemon(t *testing.T, ctx context.Context, kind string) engine.Engine {
	t.Helper()
	eng, err := engines.New(kind, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Ping(ctx); err != nil {
		t.Skipf("no daemon: %v", err)
	}
	return eng
}

func runHost(t *testing.T, ctx context.Context, r *runner.Runner, c *contract.Contract, opts runner.Options) *runner.Handle {
	t.Helper()
	h, err := r.Run(ctx, c, "vulnerable", runner.Exposure{Mode: runner.ModeHost, Bind: "127.0.0.1"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Stop(context.Background(), h) })
	if h.VerifyOK == nil || !*h.VerifyOK {
		t.Fatalf("verify failed (ready=%v):\n%s", h.Ready, h.VerifyDetail)
	}
	return h
}

// TestEmulatedImageBase runs an image published only for a foreign
// architecture through the same Preflight -> Run path the CLI uses, and checks
// it really runs as that architecture (#41 item 4). Before the fix the pull
// failed with "no matching manifest" and a multi-arch image ran natively.
func TestEmulatedImageBase(t *testing.T) {
	if os.Getenv("VULNSUITE_E2E") == "" {
		t.Skip("set VULNSUITE_E2E=1 to run against a Docker daemon")
	}
	for _, kind := range []string{"sdk", "api"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			eng := daemon(t, ctx, kind)
			host, err := eng.Info(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if host.OS != "linux" {
				t.Skipf("emulation needs a linux daemon, have %s", host.OS)
			}
			arch, foreignOnly, uname := foreignArch(host.Arch)
			// A foreign-only image (failed to pull before) and a multi-arch one
			// (ran natively before, although emulation was announced).
			for i, image := range []string{foreignOnly, "busybox:1.36.1"} {
				c, err := contract.Parse([]byte(fmt.Sprintf(`apiVersion: vulnsuite/v1
kind: Target
metadata: { id: e2e-emulated-%s-%d, summary: e2e foreign-arch image base }
base: { kind: image, image: %s }
requires: { arch: [%s] }
service:
  ports: [ { container: 8080, protocol: tcp } ]
  command: [httpd, -f, -p, "8080", -h, /]
  healthcheck: { tcp: { port: 8080 }, timeout: 60s }
states:
  vulnerable:
    verify:
      - exec: { run: "uname -m", stdout_matches: "^%s" }
`, kind, i, image, arch, uname)))
				if err != nil {
					t.Fatal(err)
				}
				d := runner.Preflight(c.Requires, host)
				if d.Action != runner.ActionEmulated || d.Platform != "linux/"+arch {
					t.Fatalf("preflight: %+v", d)
				}
				if present, _ := eng.ImageExists(ctx, image, ""); !present {
					t.Cleanup(func() { _ = eng.ImageRemove(context.Background(), image, true) })
				}
				h := runHost(t, ctx, runner.New(eng), c, runner.Options{Verify: true,
					Build: builder.Options{Pull: true, Platform: d.Platform}})
				// The api engine speaks API 1.41, which cannot inspect a
				// non-default platform of a multi-platform (containerd) store;
				// it re-pulls instead, so only the sdk engine must see it.
				if ok, err := eng.ImageExists(ctx, image, d.Platform); kind == "sdk" && (err != nil || !ok) {
					t.Fatalf("%s not present for %s after the run: %v %v", image, d.Platform, ok, err)
				}
				t.Logf("%s ran as %s: %s", image, uname, h.VerifyDetail)
			}
		})
	}
}

// TestOverlayModeOnNonRootBase builds an overlay with a mode onto a base whose
// USER is not root (#41 item 5): RUN chmod failed there with "Operation not
// permitted"; the mode now travels in the build context.
func TestOverlayModeOnNonRootBase(t *testing.T) {
	if os.Getenv("VULNSUITE_E2E") == "" {
		t.Skip("set VULNSUITE_E2E=1 to run against a Docker daemon")
	}
	for _, kind := range []string{"sdk", "api"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			eng := daemon(t, ctx, kind)
			base := "vulnsuite-e2e/nonroot-" + kind + ":1"
			df := "FROM busybox:1.36.1\nUSER 1000:1000\n"
			if err := eng.ImageBuild(ctx, engine.BuildOptions{Context: tarOf(t, map[string]string{"Dockerfile": df}), Tags: []string{base}}, nil); err != nil {
				t.Fatalf("build non-root base: %v", err)
			}
			t.Cleanup(func() { _ = eng.ImageRemove(context.Background(), base, true) })

			dir := t.TempDir()
			must(t, os.MkdirAll(filepath.Join(dir, "files"), 0o755))
			must(t, os.WriteFile(filepath.Join(dir, "files", "hello.sh"), []byte("#!/bin/sh\necho hello-from-overlay\n"), 0o644))
			c, err := contract.Parse([]byte(fmt.Sprintf(`apiVersion: vulnsuite/v1
kind: Target
metadata: { id: e2e-overlay-mode-%s, summary: e2e overlay mode on a non-root base }
base: { kind: image, image: %s }
service:
  ports: [ { container: 8080, protocol: tcp } ]
  command: [httpd, -f, -p, "8080", -h, /]
  healthcheck: { tcp: { port: 8080 }, timeout: 30s }
states:
  vulnerable:
    overlay: [ { src: files/hello.sh, dest: /opt/hello.sh, mode: "0755" } ]
    verify:
      - exec: { run: "id -u; stat -c %%a /opt/hello.sh; /opt/hello.sh", stdout_matches: "1000\\s+755\\s+hello-from-overlay" }
`, kind, base)))
			if err != nil {
				t.Fatal(err)
			}
			c.Folder = dir
			t.Cleanup(func() { _ = eng.ImageRemove(context.Background(), c.ImageTag("vulnerable"), true) })
			h := runHost(t, ctx, runner.New(eng), c, runner.Options{Verify: true, Build: builder.Options{Pull: false}})
			if !h.Image.Built || strings.Contains(h.Image.Ref, "@") {
				t.Fatalf("expected an overlay build: %+v", h.Image)
			}
		})
	}
}

func tarOf(t *testing.T, files map[string]string) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		must(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte(body))
		must(t, err)
	}
	must(t, tw.Close())
	return &buf
}
