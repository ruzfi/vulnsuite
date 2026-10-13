package runner

import (
	"fmt"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// Preflight actions.
const (
	ActionNative   = "native"   // runs natively on this host
	ActionEmulated = "emulated" // runs under qemu for a different arch
	ActionSkip     = "skip"     // the host cannot run this target
)

// Decision is the outcome of checking a target's requirements against a host.
type Decision struct {
	Action string // native | emulated | skip
	// Platform to request from the engine when emulated (e.g. "linux/amd64").
	Platform string
	// Reason explains a skip or an emulation, for the user.
	Reason string
}

// Skip reports whether the target cannot run on this host.
func (d Decision) Skip() bool { return d.Action == ActionSkip }

// Preflight decides whether a target's requirements are met by host. It is a
// pure function so it can be unit-tested without an engine.
func Preflight(req contract.Requires, host engine.HostInfo) Decision {
	hostOS, hostArch := host.OS, host.Arch
	if hostOS == "" {
		hostOS = "linux"
	}

	// Container-host OS must match (almost always linux).
	if len(req.HostOS) > 0 && !contains(req.HostOS, hostOS) {
		return Decision{Action: ActionSkip, Reason: fmt.Sprintf(
			"needs a %v container host; this host is %s", req.HostOS, hostOS)}
	}

	// KVM / nested virtualization is only usable on a linux/amd64 host.
	if req.KVM && !(hostOS == "linux" && hostArch == "amd64") {
		return Decision{Action: ActionSkip, Reason: fmt.Sprintf(
			"needs /dev/kvm + nested virtualization (a linux/amd64 host); this host is %s/%s", hostOS, hostArch)}
	}

	// Arch: native when the host arch is accepted (or none is required).
	if len(req.Arch) == 0 || contains(req.Arch, hostArch) {
		return Decision{Action: ActionNative}
	}

	// Host arch not accepted: emulate on linux when allowed, else skip.
	if req.EmulationAllowed() && hostOS == "linux" {
		return Decision{Action: ActionEmulated, Platform: "linux/" + req.Arch[0], Reason: fmt.Sprintf(
			"host is %s/%s; running %s image under emulation (slower)", hostOS, hostArch, req.Arch[0])}
	}
	return Decision{Action: ActionSkip, Reason: fmt.Sprintf(
		"needs host arch %v and emulation is off; this host is %s/%s", req.Arch, hostOS, hostArch)}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
