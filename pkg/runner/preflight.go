package runner

import (
	"fmt"
	"strings"

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
	CauseCPUFlags  = "cpu_flags" // the daemon lacks requires.cpu_flags, or they could not be read
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
		return cpuFlags(req, host)
	}

	// Host arch not accepted: emulate on linux when allowed, else skip.
	if len(req.CPUFlags) > 0 {
		return skip(CauseArch, req.Arch,
			"needs host arch %v with CPU flags %s, which rule out emulation (qemu does not provide them); this host is %s/%s",
			req.Arch, strings.Join(req.CPUFlags, ","), hostOS, hostArch)
	}
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

// cpuFlags decides a target that runs natively on the host's arch: it runs
// when the daemon has every flag in requires.cpu_flags. Flags that were not
// (or could not be) read skip it, naming them all: a target that needs them
// fails on a host without them, which must not look like a broken template.
func cpuFlags(req contract.Requires, host engine.HostInfo) Decision {
	if len(req.CPUFlags) == 0 {
		return Decision{Action: ActionNative}
	}
	want := strings.Join(req.CPUFlags, ",")
	if !host.CPUFlagsKnown {
		why := "they were not read"
		if host.CPUFlagsError != "" {
			why = "could not read them: " + host.CPUFlagsError
		}
		return skip(CauseCPUFlags, req.CPUFlags, "needs CPU flags %s; the daemon's flags are unknown (%s)", want, why)
	}
	var missing, present []string
	for _, f := range req.CPUFlags {
		if contains(host.CPUFlags, f) {
			present = append(present, f)
		} else {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		return Decision{Action: ActionNative}
	}
	has := "none of them"
	if len(present) > 0 {
		has = strings.Join(present, ",")
	}
	return skip(CauseCPUFlags, missing, "needs CPU flags [%s]; daemon has %s", strings.Join(missing, " "), has)
}

// NeedsCPUFlags reports whether deciding req on host needs the daemon's CPU
// flags, which are not read yet: everything else in req is met. A caller reads
// them (ReadCPUFlags) only then, once, and decides again.
func NeedsCPUFlags(req contract.Requires, host engine.HostInfo) bool {
	return len(req.CPUFlags) > 0 && !host.CPUFlagsKnown && host.CPUFlagsError == "" &&
		Preflight(req, host).Cause == CauseCPUFlags
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
