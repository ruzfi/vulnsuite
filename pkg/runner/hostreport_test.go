package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// hostFake answers the host report probes: the native one prints a kernel,
// kvm and cpuinfo; the amd64 one prints machine with exit code amdCode.
func hostFake(arch, machine string, amdCode int) (*enginetest.Fake, *[]engine.ContainerSpec) {
	fe := enginetest.New()
	fe.HostInfo = engine.HostInfo{OS: "linux", Arch: arch}
	var specs []engine.ContainerSpec
	fe.StartFn = func(spec engine.ContainerSpec) error {
		specs = append(specs, spec)
		code := 0
		if spec.Platform == "linux/amd64" {
			code = amdCode
		}
		fe.Exit(spec.Name, code)
		return nil
	}
	fe.LogsFn = func(spec engine.ContainerSpec) string {
		if spec.Platform == "linux/amd64" {
			return machine + "\n"
		}
		return "kernel: 6.8.0-test\nkvm: yes\nFeatures\t: fp asimd aes\n"
	}
	return fe, &specs
}

func TestHostReport(t *testing.T) {
	ctx := context.Background()

	fe, specs := hostFake("arm64", "x86_64", 0)
	rep, err := Host(ctx, fe, HostProbeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OS != "linux" || rep.Arch != "arm64" || rep.Engine == "" || rep.Kernel != "6.8.0-test" || rep.KVM == nil || !*rep.KVM ||
		strings.Join(rep.CPUFlags, " ") != "aes asimd fp" || rep.AMD64 != AMD64Emulated || rep.ProbeError != "" {
		t.Fatalf("report %+v", rep)
	}
	// The amd64 check uses its own pinned manifest, never the native ref.
	if len(*specs) != 2 || (*specs)[0].Image != HostProbeImage || (*specs)[0].Platform != "" ||
		(*specs)[1].Image != HostProbeImageAMD64 || (*specs)[1].Platform != "linux/amd64" {
		t.Fatalf("probe containers %+v", *specs)
	}
	if len(fe.Containers) != 0 {
		t.Fatal("probe containers left behind")
	}

	// An amd64 daemon is native: no emulation check.
	fe, specs = hostFake("amd64", "", 0)
	if rep, err = Host(ctx, fe, HostProbeOptions{}); err != nil || rep.AMD64 != AMD64Native || len(*specs) != 1 {
		t.Fatalf("amd64: %v %+v", err, rep)
	}

	// amd64 containers do not run.
	fe, _ = hostFake("arm64", "exec format error", 1)
	if rep, err = Host(ctx, fe, HostProbeOptions{}); err != nil || rep.AMD64 != AMD64Unavailable || !strings.Contains(rep.AMD64Detail, "exec format error") {
		t.Fatalf("no emulation: %v %+v", err, rep)
	}

	// Offline: nothing that needs the probe image is guessed.
	fe, _ = hostFake("arm64", "x86_64", 0)
	fe.FailPull = true
	rep, err = Host(ctx, fe, HostProbeOptions{})
	if err != nil || rep.ProbeError == "" || rep.Kernel != "" || rep.KVM != nil || rep.CPUFlags != nil ||
		rep.AMD64 != AMD64Unknown || !strings.Contains(rep.AMD64Detail, "pull") || rep.Arch != "arm64" {
		t.Fatalf("offline: %v %+v", err, rep)
	}
}
