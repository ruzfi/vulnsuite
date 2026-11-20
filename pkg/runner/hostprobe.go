package runner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// HostProbeImage is the image the daemon-side host probes run in: busybox,
// pinned by the digest of its multi-arch index so the daemon pulls the variant
// for its own platform.
const HostProbeImage = "busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"

// LabelHostProbe marks a host-probe container. It is not a fleet member (it has
// no LabelManaged), so `stop` and `targets` never see one.
const LabelHostProbe = "dev.vulnsuite.hostprobe"

// hostProbeTimeout bounds one probe container's run, pull excluded.
const hostProbeTimeout = time.Minute

// HostProbeOptions configures the daemon-side host probes.
type HostProbeOptions struct {
	// NoPull fails a probe whose image is not present locally instead of
	// pulling it.
	NoPull bool
	// Progress receives one line before the image is pulled (may be nil).
	Progress io.Writer
}

// cpuFlagsScript prints the /proc/cpuinfo flag lines: "flags" on x86,
// "Features" on arm64, "features" on s390x. sort -u folds the identical lines
// of every core into one.
const cpuFlagsScript = `grep -iE '^(flags|features)[[:space:]]*:' /proc/cpuinfo | sort -u`

// ReadCPUFlags reads the CPU feature flags of the daemon's machine (not the
// machine running vulnsuite: a VM or hypervisor in between can hide flags) by
// reading /proc/cpuinfo in a short-lived HostProbeImage container. When the
// cores disagree (a hybrid CPU), only the flags every core has are returned.
func ReadCPUFlags(ctx context.Context, eng engine.Engine, opts HostProbeOptions) ([]string, error) {
	out, err := runHostProbe(ctx, eng, cpuFlagsScript, opts)
	if err != nil {
		return nil, err
	}
	flags := ParseCPUFlags(out)
	if flags == nil {
		return nil, fmt.Errorf("no flags or Features line in the daemon's /proc/cpuinfo")
	}
	return flags, nil
}

// ParseCPUFlags parses /proc/cpuinfo "flags" / "Features" lines into a sorted
// flag list, keeping only the flags on every such line. It returns nil when
// there is no such line.
func ParseCPUFlags(cpuinfo string) []string {
	var common map[string]bool
	for _, line := range strings.Split(cpuinfo, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if k := strings.ToLower(strings.TrimSpace(key)); k != "flags" && k != "features" {
			continue
		}
		this := map[string]bool{}
		for _, f := range strings.Fields(val) {
			if common == nil || common[f] {
				this[f] = true
			}
		}
		common = this
	}
	if common == nil {
		return nil
	}
	out := make([]string, 0, len(common))
	for f := range common {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// WithCPUFlags returns host with its CPU flags read from the daemon, or with
// CPUFlagsError set when they cannot be read. Either way the result is final:
// NeedsCPUFlags is false for it, so they are read at most once per HostInfo.
func WithCPUFlags(ctx context.Context, eng engine.Engine, host engine.HostInfo, opts HostProbeOptions) engine.HostInfo {
	flags, err := ReadCPUFlags(ctx, eng, opts)
	if err != nil {
		host.CPUFlagsError = err.Error()
		return host
	}
	host.CPUFlags, host.CPUFlagsKnown = flags, true
	return host
}

// runHostProbe runs script under sh in a HostProbeImage container for the
// daemon's native platform, with no network and no capabilities, and returns
// its output. A non-zero exit is an error carrying the output's tail.
func runHostProbe(ctx context.Context, eng engine.Engine, script string, opts HostProbeOptions) (string, error) {
	if err := ensureProbeImage(ctx, eng, "", opts); err != nil {
		return "", err
	}
	out, code, err := runProbeContainer(ctx, eng, engine.ContainerSpec{Image: HostProbeImage, Cmd: []string{"sh", "-c", script}}, hostProbeTimeout)
	if err == nil && code != 0 {
		err = fmt.Errorf("the host probe exited %d: %s", code, strings.TrimSpace(tail(out, 400)))
	}
	return out, err
}

// ensureProbeImage makes HostProbeImage present for platform ("" = native).
func ensureProbeImage(ctx context.Context, eng engine.Engine, platform string, opts HostProbeOptions) error {
	return ensureImage(ctx, eng, HostProbeImage, platform, opts)
}

// ensureImage makes a host probe image present for platform, pulling it unless
// opts.NoPull.
func ensureImage(ctx context.Context, eng engine.Engine, ref, platform string, opts HostProbeOptions) error {
	ok, err := eng.ImageExists(ctx, ref, platform)
	if err != nil {
		return fmt.Errorf("look up the host probe image %s: %w", ref, err)
	}
	if ok {
		return nil
	}
	if opts.NoPull {
		return fmt.Errorf("the host probe image %s is not present and pulling is off (-no-pull)", ref)
	}
	if opts.Progress != nil {
		fmt.Fprintf(opts.Progress, "pulling the host probe image %s...\n", ref)
	}
	if err := eng.ImagePull(ctx, ref, platform, nil); err != nil {
		return fmt.Errorf("pull the host probe image %s: %w", ref, err)
	}
	return nil
}

// runProbeContainer creates, runs and removes a one-shot container from spec
// (hardened: no network, no capabilities, no-new-privileges) and returns its
// output and exit code. Not exiting within timeout is an error.
func runProbeContainer(ctx context.Context, eng engine.Engine, spec engine.ContainerSpec, timeout time.Duration) (string, int, error) {
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", -1, err
	}
	spec.Name = contract.ContainerNamePrefix + "hostprobe-" + hex.EncodeToString(rnd[:])
	spec.Labels = map[string]string{LabelHostProbe: "true"}
	spec.Network = &engine.NetworkAttachment{Name: "none"}
	spec.CapDrop = []string{"ALL"}
	spec.SecurityOpt = []string{"no-new-privileges:true"}
	if _, err := eng.ContainerCreate(ctx, spec); err != nil {
		return "", -1, fmt.Errorf("create the probe container: %w", err)
	}
	defer func() {
		cctx, cancel := CleanupContext(ctx)
		defer cancel()
		_ = eng.ContainerRemove(cctx, spec.Name)
	}()
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := eng.ContainerStart(rctx, spec.Name); err != nil {
		return "", -1, fmt.Errorf("start the probe container: %w", err)
	}
	code, err := eng.ContainerWait(rctx, spec.Name)
	if err != nil {
		if errors.Is(rctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return "", -1, fmt.Errorf("the probe container did not exit within %s", timeout)
		}
		return "", -1, fmt.Errorf("wait for the probe container: %w", err)
	}
	out, err := eng.ContainerLogs(rctx, spec.Name, 0)
	if err != nil {
		return "", -1, fmt.Errorf("read the probe output: %w", err)
	}
	return out, code, nil
}
