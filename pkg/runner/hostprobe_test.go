package runner

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

const x86CPUInfo = `processor	: 0
vendor_id	: GenuineIntel
flags		: fpu sse4_2 avx512f avx512bw bmi2
processor	: 1
flags		: fpu sse4_2 avx512f avx512bw bmi2
`

func TestParseCPUFlags(t *testing.T) {
	cases := map[string]struct {
		in   string
		want []string
	}{
		"x86 flags":   {x86CPUInfo, []string{"avx512bw", "avx512f", "bmi2", "fpu", "sse4_2"}},
		"arm64":       {"processor\t: 0\nFeatures\t: fp asimd evtstrm aes pmull\nCPU implementer\t: 0x61\n", []string{"aes", "asimd", "evtstrm", "fp", "pmull"}},
		"s390x":       {"features\t: esan3 zarch stfle\n", []string{"esan3", "stfle", "zarch"}},
		"hybrid core": {"flags : a b c\nflags : b c d\n", []string{"b", "c"}},
		"no flags":    {"processor : 0\nmodel name : x\n", nil},
		"empty":       {"", nil},
	}
	for name, tc := range cases {
		if got := ParseCPUFlags(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

// probeFake answers the host probe container: it exits with code and prints
// out, and records the spec it ran with.
func probeFake(t *testing.T, out string, code int) (*enginetest.Fake, *[]engine.ContainerSpec) {
	t.Helper()
	fe := enginetest.New()
	var specs []engine.ContainerSpec
	fe.StartFn = func(spec engine.ContainerSpec) error {
		specs = append(specs, spec)
		fe.Exit(spec.Name, code)
		return nil
	}
	fe.LogsFn = func(engine.ContainerSpec) string { return out }
	return fe, &specs
}

func TestReadCPUFlags(t *testing.T) {
	ctx := context.Background()
	fe, specs := probeFake(t, x86CPUInfo, 0)
	var progress strings.Builder
	flags, err := ReadCPUFlags(ctx, fe, HostProbeOptions{Progress: &progress})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(flags, []string{"avx512bw", "avx512f", "bmi2", "fpu", "sse4_2"}) {
		t.Fatalf("flags %q", flags)
	}
	// The pinned image is pulled for the daemon's own platform, and the
	// container is hardened, native, and gone afterwards.
	if len(fe.Pulls) != 1 || !strings.Contains(fe.Pulls[0], HostProbeImage) || !strings.Contains(progress.String(), "pulling the host probe image") {
		t.Fatalf("pulls %q, progress %q", fe.Pulls, progress.String())
	}
	if len(*specs) != 1 {
		t.Fatalf("%d probe containers", len(*specs))
	}
	s := (*specs)[0]
	if s.Image != HostProbeImage || s.Platform != "" || s.Network == nil || s.Network.Name != "none" ||
		!reflect.DeepEqual(s.CapDrop, []string{"ALL"}) || s.Labels[LabelHostProbe] != "true" || s.Labels[LabelManaged] != "" ||
		!strings.Contains(strings.Join(s.Cmd, " "), "/proc/cpuinfo") {
		t.Fatalf("probe spec %+v", s)
	}
	if len(fe.Containers) != 0 {
		t.Fatalf("probe container left behind: %v", fe.Containers)
	}
	// A second read reuses the image.
	if _, err := ReadCPUFlags(ctx, fe, HostProbeOptions{}); err != nil || len(fe.Pulls) != 1 {
		t.Fatalf("second read: %v, pulls %q", err, fe.Pulls)
	}
}

// The flags are never guessed: every way of not reading them is an error.
func TestReadCPUFlagsFailures(t *testing.T) {
	ctx := context.Background()

	fe, _ := probeFake(t, x86CPUInfo, 0)
	fe.FailPull = true
	if _, err := ReadCPUFlags(ctx, fe, HostProbeOptions{}); err == nil || !strings.Contains(err.Error(), "pull the host probe image") {
		t.Fatalf("offline pull: %v", err)
	}

	fe, specs := probeFake(t, x86CPUInfo, 0)
	if _, err := ReadCPUFlags(ctx, fe, HostProbeOptions{NoPull: true}); err == nil || !strings.Contains(err.Error(), "-no-pull") || len(fe.Pulls) != 0 || len(*specs) != 0 {
		t.Fatalf("-no-pull without the image: %v, pulls %q", err, fe.Pulls)
	}

	fe, _ = probeFake(t, "grep: /proc/cpuinfo: No such file or directory\n", 2)
	if _, err := ReadCPUFlags(ctx, fe, HostProbeOptions{}); err == nil || !strings.Contains(err.Error(), "exited 2") || !strings.Contains(err.Error(), "No such file") {
		t.Fatalf("non-zero exit: %v", err)
	}
	if len(fe.Containers) != 0 {
		t.Fatal("failed probe container left behind")
	}

	fe, _ = probeFake(t, "", 0)
	if _, err := ReadCPUFlags(ctx, fe, HostProbeOptions{}); err == nil || !strings.Contains(err.Error(), "no flags or Features line") {
		t.Fatalf("no flags line: %v", err)
	}
}

func TestWithCPUFlags(t *testing.T) {
	ctx := context.Background()
	base := engine.HostInfo{OS: "linux", Arch: "amd64"}
	fe, _ := probeFake(t, x86CPUInfo, 0)
	h := WithCPUFlags(ctx, fe, base, HostProbeOptions{})
	if !h.CPUFlagsKnown || h.CPUFlagsError != "" || len(h.CPUFlags) != 5 {
		t.Fatalf("read: %+v", h)
	}
	fe, _ = probeFake(t, x86CPUInfo, 0)
	fe.FailPull = true
	h = WithCPUFlags(ctx, fe, base, HostProbeOptions{})
	if h.CPUFlagsKnown || h.CPUFlagsError == "" || h.CPUFlags != nil {
		t.Fatalf("failed read: %+v", h)
	}
}
