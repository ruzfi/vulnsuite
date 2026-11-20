package runner

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
)

func boolp(b bool) *bool { return &b }

func TestPreflight(t *testing.T) {
	linuxAmd := engine.HostInfo{OS: "linux", Arch: "amd64"}
	linuxArm := engine.HostInfo{OS: "linux", Arch: "arm64"}
	winArm := engine.HostInfo{OS: "windows", Arch: "arm64"}

	cases := []struct {
		name string
		req  contract.Requires
		host engine.HostInfo
		want string
		plat string
		// cause and missing are checked on a skip.
		cause   string
		missing []string
	}{
		{"no requirements", contract.Requires{}, linuxArm, ActionNative, "", "", nil},
		{"arch matches", contract.Requires{Arch: []string{"amd64", "arm64"}}, linuxArm, ActionNative, "", "", nil},
		{"amd64-only on arm emulates", contract.Requires{Arch: []string{"amd64"}}, linuxArm, ActionEmulated, "linux/amd64", "", nil},
		{"amd64-only, emulation off, on arm skips", contract.Requires{Arch: []string{"amd64"}, Emulation: boolp(false)}, linuxArm, ActionSkip, "", CauseArch, []string{"amd64"}},
		{"amd64-only on a windows host cannot emulate", contract.Requires{Arch: []string{"amd64"}}, winArm, ActionSkip, "", CauseEmulation, []string{"amd64"}},
		{"kvm on linux/amd64 is native", contract.Requires{KVM: true, Arch: []string{"amd64"}}, linuxAmd, ActionNative, "", "", nil},
		{"kvm on arm skips", contract.Requires{KVM: true, Arch: []string{"amd64"}, Emulation: boolp(false)}, linuxArm, ActionSkip, "", CauseKVM, []string{"kvm"}},
		{"kvm on darwin-ish non-amd64 skips", contract.Requires{KVM: true}, linuxArm, ActionSkip, "", CauseKVM, []string{"kvm"}},
		{"host_os mismatch skips", contract.Requires{HostOS: []string{"windows"}}, linuxAmd, ActionSkip, "", CauseHostOS, []string{"windows"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Preflight(tc.req, tc.host)
			if d.Action != tc.want {
				t.Fatalf("action %s, want %s (reason: %s)", d.Action, tc.want, d.Reason)
			}
			if d.Action == ActionEmulated && d.Platform != tc.plat {
				t.Fatalf("platform %s, want %s", d.Platform, tc.plat)
			}
			if d.Skip() && d.Reason == "" {
				t.Fatal("skip must carry a reason")
			}
			if d.Cause != tc.cause || !reflect.DeepEqual(d.Missing, tc.missing) {
				t.Fatalf("cause %q missing %q, want %q %q (reason: %s)", d.Cause, d.Missing, tc.cause, tc.missing, d.Reason)
			}
		})
	}
}

// #119: requires.cpu_flags gates a target on the daemon's CPU features.
func TestPreflightCPUFlags(t *testing.T) {
	vbmi := contract.Requires{Arch: []string{"amd64"}, CPUFlags: []string{"avx512f", "avx512bw", "avx512vbmi", "bmi2"}}
	skylake := engine.HostInfo{OS: "linux", Arch: "amd64", CPUFlagsKnown: true, CPUFlags: []string{"avx512f", "avx512bw", "bmi2", "sse4_2"}}
	iceLake := engine.HostInfo{OS: "linux", Arch: "amd64", CPUFlagsKnown: true, CPUFlags: []string{"avx512f", "avx512bw", "avx512vbmi", "bmi2"}}
	unread := engine.HostInfo{OS: "linux", Arch: "amd64"}
	failed := engine.HostInfo{OS: "linux", Arch: "amd64", CPUFlagsError: "pull busybox: offline"}
	arm := engine.HostInfo{OS: "linux", Arch: "arm64", CPUFlagsKnown: true, CPUFlags: []string{"fp", "asimd", "aes"}}

	cases := []struct {
		name    string
		req     contract.Requires
		host    engine.HostInfo
		action  string
		cause   string
		missing []string
		reason  string // substring of the reason
	}{
		{"has every flag", vbmi, iceLake, ActionNative, "", nil, ""},
		{"amd64 without vbmi skips naming it", vbmi, skylake, ActionSkip, CauseCPUFlags, []string{"avx512vbmi"},
			"needs CPU flags [avx512vbmi]; daemon has avx512f,avx512bw,bmi2"},
		{"none of the flags", contract.Requires{CPUFlags: []string{"sgx", "rtm"}}, skylake, ActionSkip, CauseCPUFlags, []string{"sgx", "rtm"},
			"daemon has none of them"},
		// arm64 must skip, not emulate: qemu does not provide the flags.
		{"arm64 skips rather than emulating", vbmi, arm, ActionSkip, CauseArch, []string{"amd64"},
			"with CPU flags avx512f,avx512bw,avx512vbmi,bmi2, which rule out emulation"},
		{"arm64 skips even with emulation: true", contract.Requires{Arch: []string{"amd64"}, CPUFlags: []string{"bmi2"}, Emulation: boolp(true)}, arm, ActionSkip, CauseArch, []string{"amd64"}, "rule out emulation"},
		{"unread flags skip", vbmi, unread, ActionSkip, CauseCPUFlags, vbmi.CPUFlags, "the daemon's flags are unknown (they were not read)"},
		{"unreadable flags skip with the error", vbmi, failed, ActionSkip, CauseCPUFlags, vbmi.CPUFlags, "could not read them: pull busybox: offline"},
		{"arm64 flags without an arch", contract.Requires{CPUFlags: []string{"aes", "asimd"}}, arm, ActionNative, "", nil, ""},
		// The other checks come first: no flags are needed to skip these.
		{"host_os first", contract.Requires{HostOS: []string{"windows"}, CPUFlags: []string{"bmi2"}}, unread, ActionSkip, CauseHostOS, []string{"windows"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Preflight(tc.req, tc.host)
			if d.Action != tc.action || d.Cause != tc.cause || !reflect.DeepEqual(d.Missing, tc.missing) {
				t.Fatalf("got %s/%s %q (%s), want %s/%s %q", d.Action, d.Cause, d.Missing, d.Reason, tc.action, tc.cause, tc.missing)
			}
			if !strings.Contains(d.Reason, tc.reason) {
				t.Fatalf("reason %q does not contain %q", d.Reason, tc.reason)
			}
		})
	}
}

// NeedsCPUFlags asks for the flags only when they would decide the target.
func TestNeedsCPUFlags(t *testing.T) {
	vbmi := contract.Requires{Arch: []string{"amd64"}, CPUFlags: []string{"avx512vbmi"}}
	amd := engine.HostInfo{OS: "linux", Arch: "amd64"}
	cases := []struct {
		name string
		req  contract.Requires
		host engine.HostInfo
		want bool
	}{
		{"unread on amd64", vbmi, amd, true},
		{"no cpu_flags", contract.Requires{Arch: []string{"amd64"}}, amd, false},
		{"arm64 is skipped on its arch", vbmi, engine.HostInfo{OS: "linux", Arch: "arm64"}, false},
		{"kvm already fails", contract.Requires{KVM: true, CPUFlags: []string{"vmx"}}, engine.HostInfo{OS: "linux", Arch: "arm64"}, false},
		{"already read", vbmi, engine.HostInfo{OS: "linux", Arch: "amd64", CPUFlagsKnown: true}, false},
		{"already failed", vbmi, engine.HostInfo{OS: "linux", Arch: "amd64", CPUFlagsError: "offline"}, false},
	}
	for _, tc := range cases {
		if got := NeedsCPUFlags(tc.req, tc.host); got != tc.want {
			t.Errorf("%s: NeedsCPUFlags = %v, want %v", tc.name, got, tc.want)
		}
	}
}
