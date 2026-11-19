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

// Skip causes: which requirement a skipped target does not meet. They are
// stable strings a pipeline can switch on (the reason is the human text).
const (
	CauseHostOS    = "host_os"   // the daemon OS is not in requires.host_os
	CauseKVM       = "kvm"       // requires.kvm on a host that cannot provide it
	CauseArch      = "arch"      // the host arch is not in requires.arch and emulation is off
	CauseEmulation = "emulation" // emulation is allowed, but this host cannot emulate
)

// Decision is the outcome of checking a target's requirements against a host.
type Decision struct {
	Action string // native | emulated | skip
	// Platform to request from the engine when emulated (e.g. "linux/amd64").
	Platform string
	// Reason explains a skip or an emulation, for the user.
	Reason string
	// Cause is the unmet requirement of a skip (one of the Cause* constants).
	Cause string
	// Missing lists what the host lacks for a skip: the accepted OSes or
	// arches, "kvm", ... (empty when not a skip).
	Missing []string
}

// Skip reports whether the target cannot run on this host.
func (d Decision) Skip() bool { return d.Action == ActionSkip }

func skip(cause string, missing []string, format string, a ...any) Decision {
	return Decision{Action: ActionSkip, Cause: cause, Missing: append([]string(nil), missing...), Reason: fmt.Sprintf(format, a...)}
}

// Preflight decides whether a target's requirements are met by host. It is a
// pure function so it can be unit-tested without an engine.
func Preflight(req contract.Requires, host engine.HostInfo) Decision {
	hostOS, hostArch := host.OS, host.Arch
	if hostOS == "" {
		hostOS = "linux"
	}

	// Container-host OS must match (almost always linux).
	if len(req.HostOS) > 0 && !contains(req.HostOS, hostOS) {
		return skip(CauseHostOS, req.HostOS,
			"needs a %v container host; this host is %s", req.HostOS, hostOS)
	}

	// KVM / nested virtualization is only usable on a linux/amd64 host.
	if req.KVM && !(hostOS == "linux" && hostArch == "amd64") {
		return skip(CauseKVM, []string{"kvm"},
			"needs /dev/kvm + nested virtualization (a linux/amd64 host); this host is %s/%s", hostOS, hostArch)
	}

	// Arch: native when the host arch is accepted (or none is required).
	if len(req.Arch) == 0 || contains(req.Arch, hostArch) {
		return Decision{Action: ActionNative}
	}

	// Host arch not accepted: emulate on linux when allowed, else skip.
	if !req.EmulationAllowed() {
		return skip(CauseArch, req.Arch,
			"needs host arch %v and emulation is off; this host is %s/%s", req.Arch, hostOS, hostArch)
	}
	if hostOS != "linux" {
		return skip(CauseEmulation, req.Arch,
			"needs host arch %v, and a %s host cannot emulate it; this host is %s/%s", req.Arch, hostOS, hostOS, hostArch)
	}
	return Decision{Action: ActionEmulated, Platform: "linux/" + req.Arch[0], Reason: fmt.Sprintf(
		"host is %s/%s; running %s image under emulation (slower)", hostOS, hostArch, req.Arch[0])}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
