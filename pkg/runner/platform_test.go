package runner

import (
	"context"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

// Issue #41 item 4: under emulation an image-kind target and its sidecars are
// pulled and created for the emulation platform, not the daemon's default.
func TestRunPassesEmulationPlatform(t *testing.T) {
	fe := enginetest.New()
	fe.HostInfo.Arch = "arm64"
	// Native (arm64) copies are already present; they must not be used.
	for _, ref := range []string{"amd64/busybox:1.36.1", "mysql:5.7"} {
		fe.Images[ref] = true
		fe.ImagePlatforms[ref] = "linux/arm64"
	}
	r := New(fe)
	r.Reach = func(string, int, time.Duration) probes.Reach { return probes.Unreachable }
	c := &contract.Contract{
		APIVersion: contract.APIVersion,
		Kind:       contract.Kind,
		Metadata:   contract.Metadata{ID: "emu-target"},
		Base:       contract.Base{Kind: contract.BaseImage, Image: "amd64/busybox:1.36.1"},
		Service: contract.Service{
			Ports:    []contract.Port{{Container: 80, Protocol: "http"}},
			Sidecars: []contract.Sidecar{{Name: "db", Image: "mysql:5.7"}},
		},
		States: map[string]*contract.State{"vulnerable": {Name: "vulnerable"}},
	}
	h, err := r.Run(context.Background(), c, "vulnerable", DefaultExposure(),
		Options{ReadyTimeout: time.Second, Build: builder.Options{Pull: true, Platform: "linux/amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	if p := fe.Containers[h.Container].Spec.Platform; p != "linux/amd64" {
		t.Fatalf("target created for %q, want linux/amd64", p)
	}
	if len(h.Sidecars) != 1 {
		t.Fatalf("sidecars: %v", h.Sidecars)
	}
	if p := fe.Containers[h.Sidecars[0]].Spec.Platform; p != "linux/amd64" {
		t.Fatalf("sidecar created for %q, want linux/amd64", p)
	}
	for _, ref := range []string{"amd64/busybox:1.36.1", "mysql:5.7"} {
		if fe.ImagePlatforms[ref] != "linux/amd64" {
			t.Fatalf("%s not pulled for linux/amd64 (have %q, pulls %v)", ref, fe.ImagePlatforms[ref], fe.Pulls)
		}
	}
	r.Stop(context.Background(), h)

	// Natively, nothing is forced: the engine default is used.
	h, err = r.Run(context.Background(), c, "vulnerable", DefaultExposure(),
		Options{ReadyTimeout: time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if p := fe.Containers[h.Container].Spec.Platform; p != "" {
		t.Fatalf("native run forced platform %q", p)
	}
	r.Stop(context.Background(), h)
}
