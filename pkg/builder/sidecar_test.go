package builder

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// sidecarDoc has an image base, a "driver" sidecar built from sidecars/driver
// and a "db" sidecar on a prebuilt image; patched runs both from the
// sidecars' own definitions unless PATCHED adds overrides.
const sidecarDoc = `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: sidecar-build, summary: x }
base: { kind: image, image: nginx:1.27 }
service:
  ports: [ { container: 80, protocol: http } ]
  sidecars:
    - { name: driver, build: { context: sidecars/driver, build_args: { V: "2" } }, command: [sleep, infinity] }
    - { name: db, image: redis:7 }
states:
  vulnerable: {}
  patched: { PATCHED }
`

var sidecarFiles = map[string]string{
	"sidecars/driver/Dockerfile":    "FROM busybox\nCOPY run.sh /run.sh\n",
	"sidecars/driver/run.sh":        "#!/bin/sh\necho hi\n",
	"sidecars/driver/.dockerignore": "*.log\n",
	"sidecars/driver/debug.log":     "ignored\n",
	"sidecars/driver/.git/HEAD":     "ref: refs/heads/main\n",
}

func sidecarContract(t *testing.T, patched string) *contract.Contract {
	t.Helper()
	c := parseIn(t, strings.Replace(sidecarDoc, "PATCHED", patched, 1), sidecarFiles)
	if err := os.Chmod(filepath.Join(c.Folder, "sidecars", "driver", "run.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	return c
}

// sidecarBuilds returns the builds of tag.
func sidecarBuilds(fe *enginetest.Fake, tag string) []enginetest.Build {
	var out []enginetest.Build
	for _, b := range fe.Builds {
		if len(b.Tags) == 1 && b.Tags[0] == tag {
			out = append(out, b)
		}
	}
	return out
}

// Resolve builds a built sidecar's image from its context, with the context
// sent like a base build's, and reuses it on the next resolve and for the
// other state.
func TestResolveBuildsSidecar(t *testing.T) {
	c := sidecarContract(t, "")
	sc := c.Service.Sidecars[0]
	tag := c.SidecarTag(sc)
	fe := enginetest.New()
	b := New(fe)
	ctx := context.Background()
	r, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Ref != "nginx:1.27" || !r.Pulled || len(r.Sidecars) != 1 {
		t.Fatalf("resolved %+v", r)
	}
	sr := r.Sidecars[0]
	if sr.Sidecar != "driver" || sr.Ref != tag || !sr.Built || sr.BuildKind != contract.BuildKindBuild || sr.State != "vulnerable" {
		t.Fatalf("sidecar resolved %+v", sr)
	}
	builds := sidecarBuilds(fe, tag)
	if len(builds) != 1 {
		t.Fatalf("want one build of %s, got %d (all %v)", tag, len(builds), fe.Builds)
	}
	bl := builds[0]
	if bl.Dockerfile != "Dockerfile" || bl.BuildArgs["V"] != "2" {
		t.Fatalf("build options: %+v", bl)
	}
	if _, ok := bl.Files["run.sh"]; !ok || bl.Modes["run.sh"]&0o111 == 0 {
		t.Fatalf("run.sh missing or not executable in the context: %v %o", bl.Files, bl.Modes["run.sh"])
	}
	for _, gone := range []string{"debug.log", ".git/HEAD"} {
		if _, ok := bl.Files[gone]; ok {
			t.Errorf("%s must be left out of the context", gone)
		}
	}
	if bl.Labels[LabelID] != c.ID() || bl.Labels[LabelSidecar] != "driver" || bl.Labels[LabelHash] != c.SidecarHash(sc) {
		t.Fatalf("labels %v", bl.Labels)
	}
	if _, ok := bl.Labels[LabelState]; ok {
		t.Fatal("a built sidecar image is shared by the states: no state label")
	}
	// Reused: again for vulnerable, and for patched.
	for _, state := range []string{"vulnerable", "patched"} {
		r, err := b.Resolve(ctx, c, state, Options{Pull: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Sidecars) != 1 || r.Sidecars[0].Built || r.Sidecars[0].Ref != tag {
			t.Fatalf("%s: want the sidecar reused, got %+v", state, r.Sidecars)
		}
	}
	if n := len(sidecarBuilds(fe, tag)); n != 1 {
		t.Fatalf("rebuilt: %d builds", n)
	}
	// The prebuilt sidecar is left to the runner.
	for _, p := range fe.Pulls {
		if p == "redis:7" {
			t.Fatal("resolve must not pull an image sidecar")
		}
	}
	// -force rebuilds.
	r, err = b.Resolve(ctx, c, "vulnerable", Options{Pull: true, Force: true})
	if err != nil || !r.Sidecars[0].Built || len(sidecarBuilds(fe, tag)) != 2 {
		t.Fatalf("force: %+v %v", r, err)
	}
}

// A state that swaps the built sidecar for an image does not build it.
func TestResolveSkipsOverriddenSidecar(t *testing.T) {
	c := sidecarContract(t, "sidecars: { driver: { image: busybox:1.36.1 } }")
	fe := enginetest.New()
	r, err := New(fe).Resolve(context.Background(), c, "patched", Options{Pull: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Sidecars) != 0 || len(fe.Builds) != 0 {
		t.Fatalf("an overridden sidecar was built: %+v %v", r.Sidecars, fe.Builds)
	}
}

// Both states resolved in parallel share one build of the sidecar.
func TestResolveAllBuildsSidecarOnce(t *testing.T) {
	c := sidecarContract(t, "")
	fe := enginetest.New()
	jobs := []Job{{Contract: c, State: "vulnerable"}, {Contract: c, State: "patched"}}
	for i := 0; i < 2; i++ {
		outs := New(fe).ResolveAll(context.Background(), jobs, 2, Options{Pull: true, Force: i == 1}, nil)
		built := 0
		for _, o := range outs {
			if o.Err != nil {
				t.Fatal(o.Err)
			}
			if o.Resolved.Sidecars[0].Built {
				built++
			}
		}
		if built != 1 {
			t.Fatalf("round %d: the sidecar was built %d times", i, built)
		}
	}
	if n := len(sidecarBuilds(fe, c.SidecarTag(c.Service.Sidecars[0]))); n != 2 {
		t.Fatalf("want one build per round, got %d", n)
	}
}

// Platform handling matches a state's built image: built for the requested
// platform, reused only when it was built for the platform wanted now.
func TestSidecarBuildPlatform(t *testing.T) {
	c := sidecarContract(t, "")
	tag := c.SidecarTag(c.Service.Sidecars[0])
	fe := enginetest.New() // linux/amd64
	b := New(fe)
	ctx := context.Background()
	if _, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: true, Platform: "linux/arm64"}); err != nil {
		t.Fatal(err)
	}
	if bl := sidecarBuilds(fe, tag); len(bl) != 1 || bl[0].Platform != "linux/arm64" {
		t.Fatalf("emulated build: %+v", bl)
	}
	// Native run: the arm64 image is not reused.
	r, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: true})
	if err != nil || !r.Sidecars[0].Built {
		t.Fatalf("an emulated build must not be reused natively: %+v %v", r, err)
	}
	fe.ImagePlatforms[tag] = "linux/amd64"
	if r, _ := b.Resolve(ctx, c, "vulnerable", Options{Pull: true}); r.Sidecars[0].Built {
		t.Fatal("a native build must be reused natively")
	}
}

// A sidecar build failure fails the resolve, naming the sidecar.
func TestSidecarBuildFailure(t *testing.T) {
	c := sidecarContract(t, "")
	fe := enginetest.New()
	if err := os.Remove(filepath.Join(c.Folder, "sidecars", "driver", "Dockerfile")); err != nil {
		t.Fatal(err)
	}
	_, err := New(fe).Resolve(context.Background(), c, "vulnerable", Options{Pull: true})
	if err == nil || !strings.Contains(err.Error(), "sidecar-build/vulnerable: sidecar driver (build)") {
		t.Fatalf("want a sidecar build error, got %v", err)
	}
	if err := os.RemoveAll(filepath.Join(c.Folder, "sidecars")); err != nil {
		t.Fatal(err)
	}
	_, err = New(fe).Resolve(context.Background(), c, "vulnerable", Options{Pull: true})
	if err == nil || !strings.Contains(err.Error(), "build context sidecars/driver not found") {
		t.Fatalf("want a missing context error, got %v", err)
	}
}

func TestPublishSidecar(t *testing.T) {
	c := sidecarContract(t, "")
	fe := enginetest.New()
	b := New(fe)
	ctx := context.Background()
	if _, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: true}); err != nil {
		t.Fatal(err)
	}
	sc := c.Service.Sidecars[0]
	pushed, err := b.PublishSidecar(ctx, c, sc, "reg.example/vs/", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"reg.example/vs/sidecar-build:sidecar-driver-" + c.SidecarHash(sc), "reg.example/vs/sidecar-build:sidecar-driver"}
	if strings.Join(pushed, " ") != strings.Join(want, " ") || strings.Join(fe.Pushes, " ") != strings.Join(want, " ") {
		t.Fatalf("pushed %v (engine %v), want %v", pushed, fe.Pushes, want)
	}
	if _, err := b.PublishSidecar(ctx, c, c.Service.Sidecars[1], "reg.example/vs", nil); err == nil {
		t.Fatal("an image sidecar has nothing to publish")
	}
}
