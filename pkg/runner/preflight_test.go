package runner

import (
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
)

func boolp(b bool) *bool { return &b }

func TestPreflight(t *testing.T) {
	linuxAmd := engine.HostInfo{OS: "linux", Arch: "amd64"}
	linuxArm := engine.HostInfo{OS: "linux", Arch: "arm64"}

	cases := []struct {
		name string
		req  contract.Requires
		host engine.HostInfo
		want string
		plat string
	}{
		{"no requirements", contract.Requires{}, linuxArm, ActionNative, ""},
		{"arch matches", contract.Requires{Arch: []string{"amd64", "arm64"}}, linuxArm, ActionNative, ""},
		{"amd64-only on arm emulates", contract.Requires{Arch: []string{"amd64"}}, linuxArm, ActionEmulated, "linux/amd64"},
		{"amd64-only, emulation off, on arm skips", contract.Requires{Arch: []string{"amd64"}, Emulation: boolp(false)}, linuxArm, ActionSkip, ""},
		{"kvm on linux/amd64 is native", contract.Requires{KVM: true, Arch: []string{"amd64"}}, linuxAmd, ActionNative, ""},
		{"kvm on arm skips", contract.Requires{KVM: true, Arch: []string{"amd64"}, Emulation: boolp(false)}, linuxArm, ActionSkip, ""},
		{"kvm on darwin-ish non-amd64 skips", contract.Requires{KVM: true}, linuxArm, ActionSkip, ""},
		{"host_os mismatch skips", contract.Requires{HostOS: []string{"windows"}}, linuxAmd, ActionSkip, ""},
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
		})
	}
}
