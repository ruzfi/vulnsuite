package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/runner"
	"github.com/ruzfi/vulnsuite/pkg/validator"
)

const busyboxDigest = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"

// builtSidecarContract runs busybox httpd as the target and a "driver"
// sidecar built from the template's sidecars/driver context, whose script is
// run by exec in a sequence step: it proves the script was copied in from
// the context (with its exec bit), that the sidecar's environment reaches it,
// and that the sidecar resolves the target by name.
const builtSidecarContract = `apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: TEMPLATE_ID
  summary: e2e fixture, a sidecar built from a context in the template (#98)
  vuln_refs: [VS-E2E-SIDECAR-BUILD]
  severity: low
  references: [https://example.invalid]
  detection: custom-only
base: { kind: image, image: busybox:1.36.1, digest: "DIGEST" }
service:
  ports: [ { container: 8080, protocol: tcp } ]
  command: [httpd, -f, -p, "8080", -h, /etc]
  healthcheck: { tcp: { port: 8080 }, timeout: 30s }
  sidecars:
    - name: driver
      build: { context: sidecars/driver, build_args: { GREETING: hello-from-context } }
      command: [sleep, "3600"]
      environment: { MODE: e2e }
states:
  vulnerable:
    verify:
      - sequence:
          steps:
            - exec: { container: driver, run: "drive.sh", stdout_matches: "^hello-from-context mode=e2e target=up\\s*$", timeout: 20 }
`

const builtSidecarDockerfile = `FROM busybox:1.36.1@DIGEST
ARG GREETING
RUN echo "$GREETING" > /greeting
COPY drive.sh /usr/local/bin/drive.sh
`

// drive.sh is copied without a chmod: it runs only because the context
// carries its exec bit.
const builtSidecarScript = `#!/bin/sh
state=down
wget -q -O /dev/null "http://$TARGET:8080/passwd" && state=up
echo "$(cat /greeting) mode=$MODE target=$state"
`

// TestBuiltSidecar builds a sidecar's image from a context in the template
// on a real daemon (#98): it is built once, started, reachable by exec, and
// reused on the next run.
func TestBuiltSidecar(t *testing.T) {
	if os.Getenv("VULNSUITE_E2E") == "" {
		t.Skip("set VULNSUITE_E2E=1 to run against a Docker daemon")
	}
	for _, kind := range []string{"sdk", "api"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			eng := daemon(t, ctx, kind)
			// Unique per run: e2e runs sharing a daemon must not touch each
			// other's containers, networks or images.
			id := fmt.Sprintf("e2e-sidecar-build-%s-%d", kind, os.Getpid())
			dir := t.TempDir()
			driver := filepath.Join(dir, "sidecars", "driver")
			must(t, os.MkdirAll(driver, 0o755))
			must(t, os.WriteFile(filepath.Join(driver, "Dockerfile"), []byte(strings.ReplaceAll(builtSidecarDockerfile, "DIGEST", busyboxDigest)), 0o644))
			script := strings.ReplaceAll(builtSidecarScript, "$TARGET", id)
			must(t, os.WriteFile(filepath.Join(driver, "drive.sh"), []byte(script), 0o755))
			must(t, os.Chmod(filepath.Join(driver, "drive.sh"), 0o755))
			doc := strings.ReplaceAll(strings.ReplaceAll(builtSidecarContract, "TEMPLATE_ID", id), "DIGEST", busyboxDigest)
			c, err := contract.Parse([]byte(doc))
			if err != nil {
				t.Fatal(err)
			}
			c.Folder = dir
			for _, f := range (&validator.Validator{}).Check(c) {
				if f.Level == validator.Error {
					t.Fatalf("the fixture does not validate: %s", f)
				}
			}
			sc := c.Service.Sidecars[0]
			tag := c.SidecarTag(sc)

			r := runner.New(eng)
			t.Cleanup(func() {
				cctx := context.Background()
				if _, err := r.StopAll(cctx, id); err != nil {
					t.Errorf("cleanup: %v", err)
				}
				_ = eng.ImageRemove(cctx, tag, true)
			})
			// A leftover image of this exact tag (it is content-addressed)
			// would make the first run a reuse.
			_ = eng.ImageRemove(ctx, tag, true)

			run := func() *runner.Handle {
				t.Helper()
				h, err := r.Run(ctx, c, "vulnerable", runner.Exposure{Mode: runner.ModeHost, Bind: "127.0.0.1"},
					runner.Options{Verify: true, Build: builder.Options{Pull: true}})
				if err != nil {
					t.Fatal(err)
				}
				if !h.Ready || h.VerifyOK == nil || !*h.VerifyOK {
					t.Fatalf("ready=%v verify=%v:\n%s", h.Ready, h.VerifyOK, h.VerifyDetail)
				}
				if len(h.Image.Sidecars) != 1 || h.Image.Sidecars[0].Ref != tag {
					t.Fatalf("sidecar images %+v", h.Image.Sidecars)
				}
				return h
			}
			h := run()
			if !h.Image.Sidecars[0].Built {
				t.Fatal("the first run must build the sidecar image")
			}
			det, err := eng.ContainerInspect(ctx, runner.SidecarContainerName(id, "vulnerable", "driver"))
			if err != nil || !det.Running {
				t.Fatalf("driver not running: %+v %v", det, err)
			}
			t.Logf("built %s; verify:\n%s", tag, h.VerifyDetail)
			must(t, r.Stop(ctx, h))

			h = run()
			if h.Image.Sidecars[0].Built {
				t.Fatal("the second run must reuse the sidecar image")
			}
			t.Logf("reused %s", tag)
			must(t, r.Stop(ctx, h))
		})
	}
}
