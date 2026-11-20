package runner

import (
	"context"
	"fmt"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// HostProbeImageAMD64 is HostProbeImage's linux/amd64 manifest, pinned by its
// own digest. Checking whether amd64 runs under emulation pulls it by this
// reference, so the native probe image's reference is never repointed at the
// amd64 variant.
const HostProbeImageAMD64 = "busybox:1.37.0@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4"

// How a daemon runs linux/amd64 images.
const (
	AMD64Native      = "native"      // the daemon is amd64
	AMD64Emulated    = "emulated"    // an amd64 container runs, under qemu/Rosetta
	AMD64Unavailable = "unavailable" // an amd64 container does not run here
	AMD64Unknown     = "unknown"     // it could not be tried (e.g. the image cannot be pulled)
)

// HostReport is what the daemon's machine offers targets: `vulnsuite host`.
type HostReport struct {
	Engine string `json:"engine"` // the daemon's version
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	// Kernel, KVM and CPUFlags are read in a HostProbeImage container; when
	// that fails they are absent and ProbeError says why.
	Kernel string `json:"kernel,omitempty"`
	// KVM reports whether the daemon's kernel has /dev/kvm (a registered kvm
	// misc device); it does not check that containers may open it.
	KVM        *bool    `json:"kvm,omitempty"`
	CPUFlags   []string `json:"cpu_flags,omitempty"`
	ProbeError string   `json:"probe_error,omitempty"`
	// AMD64 is how linux/amd64 images run (AMD64* constants), with the error
	// behind unavailable/unknown in AMD64Detail.
	AMD64       string `json:"amd64"`
	AMD64Detail string `json:"amd64_detail,omitempty"`
	ProbeImage  string `json:"probe_image"`
}

const hostReportScript = `echo "kernel: $(uname -r)"
if [ -e /sys/class/misc/kvm ]; then echo "kvm: yes"; else echo "kvm: no"; fi
` + cpuFlagsScript

// Host reports what the daemon's machine offers. It fails only when the
// daemon cannot be asked at all (Ping/Info); probe failures are reported in
// the result (ProbeError, AMD64 unknown/unavailable).
func Host(ctx context.Context, eng engine.Engine, opts HostProbeOptions) (*HostReport, error) {
	version, err := eng.Ping(ctx)
	if err != nil {
		return nil, err
	}
	info, err := eng.Info(ctx)
	if err != nil {
		return nil, err
	}
	rep := &HostReport{Engine: version, OS: info.OS, Arch: info.Arch, ProbeImage: HostProbeImage}

	if out, err := runHostProbe(ctx, eng, hostReportScript, opts); err != nil {
		rep.ProbeError = err.Error()
	} else {
		for _, line := range strings.Split(out, "\n") {
			k, v, _ := strings.Cut(line, ":")
			switch strings.TrimSpace(k) {
			case "kernel":
				rep.Kernel = strings.TrimSpace(v)
			case "kvm":
				yes := strings.TrimSpace(v) == "yes"
				rep.KVM = &yes
			}
		}
		rep.CPUFlags = ParseCPUFlags(out)
		if rep.CPUFlags == nil {
			rep.ProbeError = "no flags or Features line in the daemon's /proc/cpuinfo"
		}
	}

	switch {
	case info.Arch == "amd64":
		rep.AMD64 = AMD64Native
	case ctx.Err() != nil:
		rep.AMD64 = AMD64Unknown
	default:
		rep.AMD64, rep.AMD64Detail = amd64Emulation(ctx, eng, opts)
	}
	return rep, ctx.Err()
}

// amd64Emulation runs `uname -m` in the linux/amd64 probe image on a non-amd64
// daemon: x86_64 means amd64 images run under emulation.
func amd64Emulation(ctx context.Context, eng engine.Engine, opts HostProbeOptions) (string, string) {
	const platform = "linux/amd64"
	if err := ensureImage(ctx, eng, HostProbeImageAMD64, platform, opts); err != nil {
		return AMD64Unknown, err.Error()
	}
	out, code, err := runProbeContainer(ctx, eng, engine.ContainerSpec{Image: HostProbeImageAMD64, Cmd: []string{"uname", "-m"}, Platform: platform}, hostProbeTimeout)
	switch got := strings.TrimSpace(out); {
	case err != nil:
		return AMD64Unavailable, err.Error()
	case code != 0:
		return AMD64Unavailable, fmt.Sprintf("an amd64 container exited %d: %s", code, strings.TrimSpace(tail(out, 300)))
	case got != "x86_64":
		return AMD64Unavailable, fmt.Sprintf("an amd64 container reports machine %q", got)
	}
	return AMD64Emulated, ""
}
