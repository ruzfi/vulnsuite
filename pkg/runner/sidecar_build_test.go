package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

const builtSidecarDoc = `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: run-sidecar-build, summary: x }
base: { kind: image, image: nginx:1.27 }
service:
  ports: [ { container: 80, protocol: http } ]
  sidecars:
    - { name: driver, build: { context: sidecars/driver }, command: [sleep, infinity], environment: { MODE: drive } }
    - { name: db, image: redis:7 }
states:
  vulnerable: {}
  patched:
    sidecars: { driver: { image: busybox:1.36.1 } }
`

func builtSidecarContract(t *testing.T) *contract.Contract {
	t.Helper()
	c, err := contract.Parse([]byte(builtSidecarDoc))
	if err != nil {
		t.Fatal(err)
	}
	c.Folder = t.TempDir()
	dir := filepath.Join(c.Folder, "sidecars", "driver")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"Dockerfile": "FROM busybox\nCOPY drive.sh /drive.sh\n", "drive.sh": "#!/bin/sh\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// run builds a built sidecar's image once, before the sidecar starts, runs
// the sidecar from it without pulling it, and reuses it on the next run.
func TestRunBuildsSidecarBeforeStart(t *testing.T) {
	c := builtSidecarContract(t)
	tag := c.SidecarTag(c.Service.Sidecars[0])
	fe := enginetest.New()
	driver := SidecarContainerName(c.ID(), "vulnerable", "driver")
	builtAtStart := -1
	fe.StartFn = func(spec engine.ContainerSpec) error {
		if spec.Name == driver {
			builtAtStart = 0
			for _, b := range fe.Builds {
				if b.Tags[0] == tag {
					builtAtStart++
				}
			}
		}
		return nil
	}
	r := New(fe)
	r.Reach = func(string, int, time.Duration) probes.Reach { return probes.Unreachable }
	ctx := context.Background()
	h, err := r.Run(ctx, c, "vulnerable", DefaultExposure(), Options{Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if builtAtStart != 1 {
		t.Fatalf("the driver started with %d builds of %s done, want 1", builtAtStart, tag)
	}
	if len(h.Image.Sidecars) != 1 || !h.Image.Sidecars[0].Built || h.Image.Sidecars[0].Ref != tag {
		t.Fatalf("handle image sidecars: %+v", h.Image.Sidecars)
	}
	spec := fe.Containers[driver].Spec
	if spec.Image != tag || strings.Join(spec.Cmd, " ") != "sleep infinity" || len(spec.Env) != 1 || spec.Env[0] != "MODE=drive" {
		t.Fatalf("driver spec: image %s cmd %v env %v", spec.Image, spec.Cmd, spec.Env)
	}
	if spec.Labels[LabelRole] != RoleSidecar || spec.Network == nil || spec.Network.Aliases[0] != "driver" {
		t.Fatalf("driver labels/network: %v %+v", spec.Labels, spec.Network)
	}
	if db := fe.Containers[SidecarContainerName(c.ID(), "vulnerable", "db")]; db == nil || db.Spec.Image != "redis:7" {
		t.Fatal("the image sidecar must run as before")
	}
	for _, p := range fe.Pulls {
		if p == tag {
			t.Fatal("a built sidecar image must never be pulled")
		}
	}
	pulledDB := 0
	for _, p := range fe.Pulls {
		if p == "redis:7" {
			pulledDB++
		}
	}
	if pulledDB != 1 {
		t.Fatalf("the image sidecar was pulled %d times", pulledDB)
	}

	// The next run reuses the image.
	builtAtStart = -1
	h, err = r.Run(ctx, c, "vulnerable", DefaultExposure(), Options{Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if builtAtStart != 1 || h.Image.Sidecars[0].Built {
		t.Fatalf("second run: %d builds at start, built=%v", builtAtStart, h.Image.Sidecars[0].Built)
	}
	if err := r.Stop(ctx, h); err != nil {
		t.Fatal(err)
	}
}

// A state that swaps the built sidecar for an image runs (and pulls) that
// image and builds nothing.
func TestRunOverriddenBuiltSidecar(t *testing.T) {
	c := builtSidecarContract(t)
	fe := enginetest.New()
	r := New(fe)
	r.Reach = func(string, int, time.Duration) probes.Reach { return probes.Unreachable }
	h, err := r.Run(context.Background(), c, "patched", DefaultExposure(), Options{Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fe.Builds) != 0 || len(h.Image.Sidecars) != 0 {
		t.Fatalf("an overridden sidecar was built: %v", fe.Builds)
	}
	if got := fe.Containers[SidecarContainerName(c.ID(), "patched", "driver")].Spec.Image; got != "busybox:1.36.1" {
		t.Fatalf("driver ran %s", got)
	}
}

// A failing sidecar build fails the run before anything starts.
func TestRunSidecarBuildFailure(t *testing.T) {
	c := builtSidecarContract(t)
	fe := enginetest.New()
	fe.FailBuild = "boom"
	_, err := New(fe).Run(context.Background(), c, "vulnerable", DefaultExposure(), Options{Build: builder.Options{Pull: true}})
	if err == nil || !strings.Contains(err.Error(), "sidecar driver (build): boom") {
		t.Fatalf("want the sidecar build error, got %v", err)
	}
	if len(fe.Containers) != 0 {
		t.Fatalf("containers left: %v", fe.Containers)
	}
}
