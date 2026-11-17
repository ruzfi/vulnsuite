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

func parseIn(t *testing.T, doc string, files map[string]string) *contract.Contract {
	t.Helper()
	c, err := contract.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	c.Folder = t.TempDir()
	for rel, body := range files {
		p := filepath.Join(c.Folder, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

const overlayDoc = `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: overlay-mode, summary: x }
base: { kind: image, image: alpine:3 }
service: { ports: [ { container: 80, protocol: http } ] }
states:
  vulnerable:
    overlay:
      - { src: files/run.sh, dest: /usr/local/bin/run.sh, mode: "0755" }
      - { src: files/conf, dest: /etc/app.conf }
`

// Issue #41 item 5: an overlay's mode is set in the build-context tar header,
// not with RUN chmod (which fails on non-root and shell-less bases).
func TestOverlayModeInTarHeader(t *testing.T) {
	c := parseIn(t, overlayDoc, map[string]string{"files/run.sh": "#!/bin/sh\n", "files/conf": "x=1\n"})
	fe := enginetest.New()
	if _, err := New(fe).Resolve(context.Background(), c, "vulnerable", Options{Pull: true}); err != nil {
		t.Fatal(err)
	}
	bl := fe.Builds[0]
	if df := bl.Files["Dockerfile"]; strings.Contains(df, "RUN") || !strings.Contains(df, "COPY overlay_0_run.sh /usr/local/bin/run.sh\n") {
		t.Fatalf("overlay Dockerfile must only COPY:\n%s", df)
	}
	if m := bl.Modes["overlay_0_run.sh"]; m != 0o755 {
		t.Fatalf("run.sh mode in tar = %o, want 755", m)
	}
	if m := bl.Modes["overlay_1_app.conf"]; m != 0o644 {
		t.Fatalf("conf mode in tar = %o, want 644 (default)", m)
	}
}

const imageDoc = `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: emu-image, summary: x }
base: { kind: image, image: amd64/busybox:1.36.1 }
service: { ports: [ { container: 80, protocol: http } ] }
states:
  vulnerable: {}
`

// Issue #41 item 4: an image-kind base is pulled for the emulation platform,
// and a native copy already present is not mistaken for it.
func TestImageKindPullsForPlatform(t *testing.T) {
	c := parseIn(t, imageDoc, nil)
	fe := enginetest.New()
	fe.HostInfo.Arch = "arm64"
	ref := "amd64/busybox:1.36.1"
	// A native (arm64) image of the same ref is already present.
	fe.Images[ref] = true
	fe.ImagePlatforms[ref] = "linux/arm64"
	b := New(fe)
	ctx := context.Background()
	r, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: true, Platform: "linux/amd64"})
	if err != nil || !r.Pulled || r.Ref != ref {
		t.Fatalf("expected a platform pull: %+v %v", r, err)
	}
	if fe.ImagePlatforms[ref] != "linux/amd64" {
		t.Fatalf("pulled for %q, want linux/amd64", fe.ImagePlatforms[ref])
	}
	// Now present for amd64: reused.
	r, err = b.Resolve(ctx, c, "vulnerable", Options{Pull: true, Platform: "linux/amd64"})
	if err != nil || r.Pulled {
		t.Fatalf("expected reuse: %+v %v", r, err)
	}
	// Pulling disabled and only a native copy present: a clear error.
	fe.ImagePlatforms[ref] = "linux/arm64"
	if _, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: false, Platform: "linux/amd64"}); err == nil || !strings.Contains(err.Error(), "for linux/amd64") {
		t.Fatalf("want a not-present-for-platform error, got %v", err)
	}
}

// Issue #41 items 1 and 4: a built tag is reused only when it was built for the
// platform wanted now (the platform is not part of the content hash).
func TestBuiltTagReusedOnlyForSamePlatform(t *testing.T) {
	c := parseIn(t, overlayDoc, map[string]string{"files/run.sh": "#!/bin/sh\n", "files/conf": "x=1\n"})
	fe := enginetest.New() // linux/amd64 host
	b := New(fe)
	ctx := context.Background()
	if r, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: true}); err != nil || !r.Built {
		t.Fatalf("native build: %+v %v", r, err)
	}
	// Recorded as native for the tests below.
	fe.ImagePlatforms[c.ImageTag("vulnerable")] = "linux/amd64"
	if r, _ := b.Resolve(ctx, c, "vulnerable", Options{Pull: true}); r.Built {
		t.Fatal("native image must be reused natively")
	}
	r, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: true, Platform: "linux/arm64"})
	if err != nil || !r.Built || fe.Builds[len(fe.Builds)-1].Platform != "linux/arm64" {
		t.Fatalf("emulated resolve after a native build must rebuild for arm64: %+v %v", r, err)
	}
	if r, _ := b.Resolve(ctx, c, "vulnerable", Options{Pull: true, Platform: "linux/arm64"}); r.Built {
		t.Fatal("arm64 image must be reused for arm64")
	}
	// Back to native: the arm64 image under the tag is not reused.
	if r, _ := b.Resolve(ctx, c, "vulnerable", Options{Pull: true}); !r.Built || fe.Builds[len(fe.Builds)-1].Platform != "" {
		t.Fatal("native resolve after an emulated build must rebuild natively")
	}
}

// Issue #41 item 3: Job.Platform overrides Options.Platform per job.
func TestResolveAllJobPlatform(t *testing.T) {
	a := parseIn(t, overlayDoc, map[string]string{"files/run.sh": "#!/bin/sh\n", "files/conf": "x=1\n"})
	fe := enginetest.New()
	s := store(t)
	apache, err := s.LoadSelector("apache-httpd-2.4.49-cve-2021-41773")
	if err != nil {
		t.Fatal(err)
	}
	out := New(fe).ResolveAll(context.Background(), []Job{
		{Contract: a, State: "vulnerable", Platform: "linux/arm64"},
		{Contract: apache, State: "vulnerable"},
	}, 2, Options{Pull: true}, nil)
	for _, o := range out {
		if o.Err != nil {
			t.Fatal(o.Err)
		}
	}
	plat := map[string]string{}
	for _, bl := range fe.Builds {
		plat[bl.Tags[0]] = bl.Platform
	}
	if plat[a.ImageTag("vulnerable")] != "linux/arm64" || plat[apache.ImageTag("vulnerable")] != "" {
		t.Fatalf("per-job platforms: %v", plat)
	}
	if fe.ImagePlatforms["httpd:2.4.49"] != "" || fe.ImagePlatforms["alpine:3"] != "linux/arm64" {
		t.Fatalf("overlay bases must be pulled for their job's platform: %v", fe.ImagePlatforms)
	}
}
