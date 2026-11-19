package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/runner"
)

const (
	probeFails  = `requires: { probe: { run: "grep -qw avx512vbmi /proc/cpuinfo", reason: "needs AVX-512 VBMI" } }`
	probePasses = `requires: { probe: { run: "true", reason: "never" } }`
)

// probeCLIFake is a lifecycle fake whose requires.probe containers exit 1 when
// their command greps for avx512vbmi and 0 otherwise; *n counts them.
func probeCLIFake(t *testing.T, n *int) *enginetest.Fake {
	fe := lifecycleFake(t)
	serve := fe.StartFn
	fe.StartFn = func(spec engine.ContainerSpec) error {
		if spec.Labels[runner.LabelHostProbe] != "" {
			*n++
			code := 0
			if strings.Contains(strings.Join(spec.Cmd, " "), "avx512vbmi") {
				code = 1
			}
			fe.Exit(spec.Name, code)
			return nil
		}
		return serve(spec)
	}
	return fe
}

// #119 item 2: a failing requires.probe is a skip, not a failure, in run
// -json (bare and -summary); -ignore-requires runs the target without it.
func TestRunRequiresProbeSkips(t *testing.T) {
	isolateHome(t)
	root := lifecycleTemplates(t, map[string]string{"aaa-probe-fails": probeFails, "bbb-probe-passes": probePasses},
		"aaa-probe-fails", "bbb-probe-passes")
	args := func(extra ...string) []string {
		return append([]string{"-json", "-T", root, "run", "-t", "misc", "-expose", "host", "-detach", "-no-verify",
			"-ready-timeout", "1s", "-nuclei-templates", t.TempDir()}, extra...)
	}
	n := 0
	fe := probeCLIFake(t, &n)
	code, out, errOut := run(t, fe, args("-summary")...)
	sum := runSummaryOf(t, out)
	if code != ExitOK || len(sum.Targets) != 1 || sum.Targets[0].ID != "bbb-probe-passes" || len(sum.Failed) != 0 || n != 2 {
		t.Fatalf("%d, %d probe(s)\n%s\n%s", code, n, out, errOut)
	}
	if len(sum.Skipped) != 1 {
		t.Fatalf("skipped: %+v", sum.Skipped)
	}
	e := sum.Skipped[0]
	if e.ID != "aaa-probe-fails" || e.Reason != reasonRequires || e.Cause != "probe" || !strings.HasPrefix(e.Detail, "needs AVX-512 VBMI (") {
		t.Fatalf("skip entry: %+v", e)
	}
	if fe.Containers["vulnsuite-aaa-probe-fails-vulnerable"] != nil {
		t.Fatal("the skipped target was started")
	}

	// The bare array: only the started target, and the run succeeds.
	n = 0
	fe = probeCLIFake(t, &n)
	code, out, errOut = run(t, fe, args()...)
	var handles []runner.Handle
	if err := json.Unmarshal([]byte(out), &handles); err != nil || code != ExitOK || len(handles) != 1 || handles[0].ID != "bbb-probe-passes" {
		t.Fatalf("bare: %d %v\n%s\n%s", code, err, out, errOut)
	}
	if !strings.Contains(errOut, "skip aaa-probe-fails: needs AVX-512 VBMI") {
		t.Fatalf("skip not reported:\n%s", errOut)
	}

	// -ignore-requires: both run, no probe.
	n = 0
	fe = probeCLIFake(t, &n)
	code, out, errOut = run(t, fe, args("-summary", "-ignore-requires")...)
	if sum = runSummaryOf(t, out); code != ExitOK || len(sum.Targets) != 2 || n != 0 {
		t.Fatalf("-ignore-requires: %d, %d probe(s)\n%s\n%s", code, n, out, errOut)
	}
}

// info and list name the probe by its reason.
func TestInfoShowsRequiresProbe(t *testing.T) {
	isolateHome(t)
	root := lifecycleTemplates(t, map[string]string{"aaa-probe-fails": probeFails}, "aaa-probe-fails")
	fe := enginetest.New()
	if code, out, errOut := run(t, fe, "-T", root, "info", "aaa-probe-fails"); code != ExitOK || !strings.Contains(out, "probe (needs AVX-512 VBMI)") {
		t.Fatalf("info: %d\n%s\n%s", code, out, errOut)
	}
	if code, out, errOut := run(t, fe, "-T", root, "list"); code != ExitOK || !strings.Contains(out, "probe (needs AVX-512 VBMI)") {
		t.Fatalf("list: %d\n%s\n%s", code, out, errOut)
	}
}

// The same in build -json: a probe-skipped job is in skipped (not built, not
// failed, not pushed), and absent from the bare array.
func TestBuildRequiresProbeSkips(t *testing.T) {
	isolateHome(t)
	root := lifecycleTemplates(t, map[string]string{"aaa-probe-fails": probeFails, "bbb-probe-passes": probePasses},
		"aaa-probe-fails", "bbb-probe-passes")
	n := 0
	fe := probeCLIFake(t, &n)
	code, out, errOut := run(t, fe, "-json", "-T", root, "build", "-t", "misc", "-state", "vulnerable", "-summary")
	var sum buildSummary
	if err := json.Unmarshal([]byte(out), &sum); err != nil || code != ExitOK {
		t.Fatalf("%d %v\n%s\n%s", code, err, out, errOut)
	}
	if len(sum.Built) != 1 || sum.Built[0].ID != "bbb-probe-passes" || len(sum.Failed) != 0 || len(sum.Skipped) != 1 ||
		sum.Skipped[0].Cause != "probe" || sum.Skipped[0].State != "vulnerable" || n != 2 {
		t.Fatalf("%d probe(s)\n%s", n, out)
	}

	n = 0
	fe = probeCLIFake(t, &n)
	code, out, errOut = run(t, fe, "-json", "-T", root, "build", "-t", "misc", "-state", "vulnerable")
	var results []buildResult
	if err := json.Unmarshal([]byte(out), &results); err != nil || code != ExitOK || len(results) != 1 || results[0].ID != "bbb-probe-passes" {
		t.Fatalf("bare: %d %v\n%s\n%s", code, err, out, errOut)
	}

	// -push: the skipped job is not pushed.
	n = 0
	fe = probeCLIFake(t, &n)
	code, out, errOut = run(t, fe, "-T", root, "build", "-t", "misc", "-state", "vulnerable", "-push", "-registry", "reg.example/vs")
	if code != ExitOK || strings.Contains(strings.Join(fe.Pushes, " "), "aaa-probe-fails") || len(fe.Pushes) == 0 {
		t.Fatalf("push: %d %q\n%s\n%s", code, fe.Pushes, out, errOut)
	}
}
