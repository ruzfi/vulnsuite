package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/runner"
)

// hostCLIFake is an arm64 daemon whose amd64 containers run (emulated) and
// whose cpuinfo lists flags.
func hostCLIFake(t *testing.T, flags string) *enginetest.Fake {
	fe := enginetest.New()
	fe.HostInfo = engine.HostInfo{OS: "linux", Arch: "arm64"}
	fe.StartFn = func(spec engine.ContainerSpec) error {
		fe.Exit(spec.Name, 0)
		return nil
	}
	fe.LogsFn = func(spec engine.ContainerSpec) string {
		if spec.Platform == "linux/amd64" {
			return "x86_64\n"
		}
		return "kernel: 6.8.0-test\nkvm: no\nflags : " + flags + "\n"
	}
	return fe
}

// #119 item 3: vulnsuite host.
func TestHostCommand(t *testing.T) {
	isolateHome(t)
	fe := hostCLIFake(t, "fpu bmi2 avx512f")
	code, out, errOut := run(t, fe, "host")
	for _, want := range []string{"linux/arm64", "6.8.0-test", "/dev/kvm     no", "avx512f bmi2 fpu (3)", "amd64        emulated", runner.HostProbeImage} {
		if !strings.Contains(out, want) {
			t.Fatalf("host output lacks %q: %d\n%s\n%s", want, code, out, errOut)
		}
	}
	if code != ExitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}

	code, out, errOut = run(t, hostCLIFake(t, "fpu"), "-json", "host")
	var rep runner.HostReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != ExitOK || rep.Arch != "arm64" || rep.KVM == nil || *rep.KVM ||
		rep.AMD64 != "emulated" || strings.Join(rep.CPUFlags, ",") != "fpu" {
		t.Fatalf("-json: %d %v\n%s\n%s", code, err, out, errOut)
	}

	// Offline: the report says unknown, with the reason, and the command fails.
	fe = hostCLIFake(t, "fpu")
	fe.FailPull = true
	code, out, errOut = run(t, fe, "host")
	if code == ExitOK || !strings.Contains(out, "cpu flags    unknown (pull the host probe image") || !strings.Contains(out, "amd64        unknown") ||
		!strings.Contains(errOut, "could not read") {
		t.Fatalf("offline: %d\n%s\n%s", code, out, errOut)
	}
	code, out, _ = run(t, fe, "-json", "host", "-no-pull")
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code == ExitOK || !strings.Contains(rep.ProbeError, "-no-pull") || len(fe.Pulls) != 0 {
		t.Fatalf("-json -no-pull: %d %v\n%s", code, err, out)
	}
}

// list -runnable hides what this daemon cannot run.
func TestListRunnable(t *testing.T) {
	isolateHome(t)
	root := lifecycleTemplates(t, map[string]string{
		"aaa-vbmi":    vbmiRequires,                        // amd64 + flags: not on arm64
		"bbb-windows": "requires: { host_os: [windows] }",  // never on linux
		"ccc-asimd":   "requires: { cpu_flags: [asimd] }",  // needs the flags read
		"ddd-amd64":   "requires: { arch: [amd64] }",       // emulated: runnable
		"eee-sse":     "requires: { cpu_flags: [sse4_2] }", // missing on this arm64
	}, "aaa-vbmi", "bbb-windows", "ccc-asimd", "ddd-amd64", "eee-sse", "fff-plain")
	fe := hostCLIFake(t, "fp asimd")
	code, out, errOut := run(t, fe, "-json", "-T", root, "list", "-runnable")
	var rows []listRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil || code != ExitOK {
		t.Fatalf("%d %v\n%s\n%s", code, err, out, errOut)
	}
	var ids []string
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	if got := strings.Join(ids, ","); got != "ccc-asimd,ddd-amd64,fff-plain" {
		t.Fatalf("runnable: %s\n%s", got, errOut)
	}
	// Without -runnable, list never asks the daemon.
	fe = enginetest.New()
	fe.ListErr = nil
	if code, out, _ = run(t, fe, "-json", "-T", root, "list"); code != ExitOK || strings.Count(out, `"id"`) != 6 || len(fe.Pulls) != 0 {
		t.Fatalf("plain list: %d\n%s", code, out)
	}
}
