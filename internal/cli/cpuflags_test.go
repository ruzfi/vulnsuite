package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/runner"
)

const vbmiRequires = "requires: { arch: [amd64], cpu_flags: [avx512f, avx512bw, avx512vbmi, bmi2] }"

// cpuFlagsFake is a lifecycle fake whose host probe container prints flags as
// /proc/cpuinfo would (or fails to pull its image), counting probe runs.
func cpuFlagsFake(t *testing.T, flags string, probes *int) *enginetest.Fake {
	fe := lifecycleFake(t)
	serve := fe.StartFn
	fe.StartFn = func(spec engine.ContainerSpec) error {
		if spec.Labels[runner.LabelHostProbe] != "" {
			*probes++
			fe.Exit(spec.Name, 0)
			return nil
		}
		return serve(spec)
	}
	fe.LogsFn = func(spec engine.ContainerSpec) string {
		if spec.Labels[runner.LabelHostProbe] != "" {
			return "flags\t\t: " + flags + "\n"
		}
		return ""
	}
	return fe
}

func runSummaryOf(t *testing.T, out string) runSummary {
	t.Helper()
	var sum runSummary
	if err := json.Unmarshal([]byte(out), &sum); err != nil {
		t.Fatalf("stdout is not the summary: %v\n%s", err, out)
	}
	return sum
}

// #119 item 1: a cpu_flags target is skipped, naming the missing flags, on a
// daemon without them, and runs on one that has them. The flags are read once
// per invocation, and only when a selected target needs them.
func TestRunCPUFlags(t *testing.T) {
	isolateHome(t)
	root := lifecycleTemplates(t, map[string]string{"aaa-vbmi": vbmiRequires, "bbb-vbmi": vbmiRequires}, "aaa-vbmi", "bbb-vbmi", "ccc-plain")
	args := func(extra ...string) []string {
		return append([]string{"-json", "-T", root, "run", "-summary", "-expose", "host", "-detach", "-no-verify",
			"-ready-timeout", "1s", "-nuclei-templates", t.TempDir()}, extra...)
	}

	// amd64 without VBMI (Skylake): both skipped, one probe container.
	probes := 0
	fe := cpuFlagsFake(t, "fpu avx512f avx512bw bmi2", &probes)
	code, out, errOut := run(t, fe, args("-t", "misc")...)
	sum := runSummaryOf(t, out)
	if code != ExitOK || len(sum.Targets) != 1 || sum.Targets[0].ID != "ccc-plain" || probes != 1 {
		t.Fatalf("skylake: %d, %d probe(s)\n%s\n%s", code, probes, out, errOut)
	}
	for _, e := range sum.Skipped {
		if e.Reason != reasonRequires || e.Cause != "cpu_flags" || strings.Join(e.Missing, ",") != "avx512vbmi" ||
			!strings.Contains(e.Detail, "needs CPU flags [avx512vbmi]; daemon has avx512f,avx512bw,bmi2") {
			t.Fatalf("skip entry: %+v", e)
		}
	}
	if len(sum.Skipped) != 2 {
		t.Fatalf("skipped: %+v", sum.Skipped)
	}

	// amd64 with VBMI: runs.
	probes = 0
	fe = cpuFlagsFake(t, "fpu avx512f avx512bw avx512vbmi bmi2", &probes)
	code, out, errOut = run(t, fe, args("-t", "aaa-vbmi")...)
	if sum = runSummaryOf(t, out); code != ExitOK || len(sum.Targets) != 1 || len(sum.Skipped) != 0 || probes != 1 {
		t.Fatalf("ice lake: %d\n%s\n%s", code, out, errOut)
	}

	// arm64: skipped on its arch, never emulated, no probe needed.
	probes = 0
	fe = cpuFlagsFake(t, "fp asimd", &probes)
	fe.HostInfo = engine.HostInfo{OS: "linux", Arch: "arm64"}
	code, out, errOut = run(t, fe, args("-t", "aaa-vbmi")...)
	sum = runSummaryOf(t, out)
	if code == ExitOK || len(sum.Skipped) != 1 || sum.Skipped[0].Cause != "arch" || probes != 0 ||
		!strings.Contains(sum.Skipped[0].Detail, "avx512vbmi") || len(fe.Containers) != 0 {
		t.Fatalf("arm64: %d, %d probe(s)\n%s\n%s", code, probes, out, errOut)
	}

	// No selected target sets cpu_flags: no probe.
	probes = 0
	fe = cpuFlagsFake(t, "", &probes)
	if code, out, errOut = run(t, fe, args("-t", "ccc-plain")...); code != ExitOK || probes != 0 {
		t.Fatalf("plain: %d, %d probe(s)\n%s\n%s", code, probes, out, errOut)
	}

	// -ignore-requires runs it anyway, without reading the flags.
	probes = 0
	fe = cpuFlagsFake(t, "fpu", &probes)
	code, out, errOut = run(t, fe, args("-t", "aaa-vbmi", "-ignore-requires")...)
	if sum = runSummaryOf(t, out); code != ExitOK || len(sum.Targets) != 1 || probes != 0 {
		t.Fatalf("-ignore-requires: %d, %d probe(s)\n%s\n%s", code, probes, out, errOut)
	}
}

// Flags that cannot be read (offline: the probe image cannot be pulled) are
// unknown: the target is skipped and the cause is said, never assumed present.
func TestRunCPUFlagsUnreadable(t *testing.T) {
	isolateHome(t)
	root := lifecycleTemplates(t, map[string]string{"aaa-vbmi": vbmiRequires}, "aaa-vbmi", "ccc-plain")
	probes := 0
	fe := cpuFlagsFake(t, "avx512f avx512bw avx512vbmi bmi2", &probes)
	fe.PullFn = func(ref string) error {
		if ref == runner.HostProbeImage {
			return errFake("dial tcp: lookup registry-1.docker.io: no such host")
		}
		return nil
	}
	code, out, errOut := run(t, fe, "-json", "-T", root, "run", "-t", "misc", "-summary", "-expose", "host", "-detach",
		"-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir())
	sum := runSummaryOf(t, out)
	if code != ExitOK || len(sum.Targets) != 1 || len(sum.Skipped) != 1 || probes != 0 {
		t.Fatalf("%d\n%s\n%s", code, out, errOut)
	}
	e := sum.Skipped[0]
	if e.Cause != "cpu_flags" || len(e.Missing) != 4 || !strings.Contains(e.Detail, "the daemon's flags are unknown") ||
		!strings.Contains(e.Detail, "no such host") {
		t.Fatalf("skip entry: %+v", e)
	}
	if !strings.Contains(errOut, "warning: could not read the daemon's CPU flags") {
		t.Fatalf("no warning:\n%s", errOut)
	}
}

// build preflights cpu_flags the same way.
func TestBuildCPUFlags(t *testing.T) {
	isolateHome(t)
	root := lifecycleTemplates(t, map[string]string{"aaa-vbmi": vbmiRequires}, "aaa-vbmi", "ccc-plain")
	probes := 0
	fe := cpuFlagsFake(t, "fpu bmi2", &probes)
	code, out, errOut := run(t, fe, "-json", "-T", root, "build", "-t", "misc", "-state", "vulnerable", "-summary")
	var sum buildSummary
	if err := json.Unmarshal([]byte(out), &sum); err != nil || code != ExitOK {
		t.Fatalf("%d %v\n%s\n%s", code, err, out, errOut)
	}
	if len(sum.Built) != 1 || sum.Built[0].ID != "ccc-plain" || len(sum.Skipped) != 1 || probes != 1 ||
		sum.Skipped[0].Cause != "cpu_flags" || strings.Join(sum.Skipped[0].Missing, ",") != "avx512f,avx512bw,avx512vbmi" {
		t.Fatalf("%d probe(s)\n%s", probes, out)
	}
}

// info and list show cpu_flags.
func TestInfoAndListShowCPUFlags(t *testing.T) {
	isolateHome(t)
	root := lifecycleTemplates(t, map[string]string{"aaa-vbmi": vbmiRequires}, "aaa-vbmi", "ccc-plain")
	fe := enginetest.New()
	code, out, errOut := run(t, fe, "-T", root, "info", "aaa-vbmi")
	if code != ExitOK || !strings.Contains(out, "arch amd64, cpu_flags avx512f,avx512bw,avx512vbmi,bmi2") {
		t.Fatalf("info: %d\n%s\n%s", code, out, errOut)
	}
	code, out, errOut = run(t, fe, "-T", root, "list", "-variants")
	if code != ExitOK || !strings.Contains(out, "REQUIRES") || !strings.Contains(out, "cpu_flags avx512f,avx512bw,avx512vbmi,bmi2") {
		t.Fatalf("list: %d\n%s\n%s", code, out, errOut)
	}
	code, out, _ = run(t, fe, "-json", "-T", root, "list", "-variants")
	var rows []listRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil || code != ExitOK || len(rows) != 2 {
		t.Fatalf("list -json: %v\n%s", err, out)
	}
	for _, r := range rows {
		switch {
		case r.ID == "aaa-vbmi" && (r.Requires == nil || len(r.Requires.CPUFlags) != 4):
			t.Fatalf("aaa-vbmi row: %+v", r)
		case r.ID == "ccc-plain" && r.Requires != nil:
			t.Fatalf("ccc-plain row has requires: %+v", r.Requires)
		}
	}
}

type errFake string

func (e errFake) Error() string { return string(e) }
