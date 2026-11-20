package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// summaryTemplates writes lifecycle templates covering every way a selected
// target can end up not running: a requires mismatch, host access, a missing
// patched state, a start failure, plus two that run.
func summaryTemplates(t *testing.T) string {
	t.Helper()
	root := lifecycleTemplates(t, map[string]string{"bbb-windows-only": "requires: { host_os: [windows] }"},
		"aaa-ok", "bbb-windows-only", "ccc-host-access", "ddd-fails", "eee-ok", "fff-vuln-only")
	patch := func(id, old, new string) {
		p := root + "/misc/" + id + "/contract.yaml"
		writeFile(t, p, strings.Replace(readFile(t, p), old, new, 1))
	}
	patch("ccc-host-access", "service:\n", "service:\n  cap_add: [SYS_ADMIN]\n")
	patch("fff-vuln-only", "  patched:\n    environment: { MODE: patched }\n", "")
	return root
}

func summaryFake(t *testing.T) *enginetest.Fake {
	fe := lifecycleFake(t)
	serve := fe.StartFn
	fe.StartFn = func(spec engine.ContainerSpec) error {
		if strings.HasPrefix(spec.Name, "vulnsuite-ddd-fails-") {
			return errors.New("boom: port in use")
		}
		return serve(spec)
	}
	return fe
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// checkRequiresCause checks that the requires skip of bbb-windows-only names
// its cause and what the host lacks (#119 item 4), and that no other skip
// carries a cause.
func checkRequiresCause(t *testing.T, skipped []outcomeEntry, out string) {
	t.Helper()
	for _, e := range skipped {
		switch {
		case e.ID == "bbb-windows-only":
			if e.Cause != "host_os" || strings.Join(e.Missing, ",") != "windows" || e.Detail == "" {
				t.Fatalf("requires skip without its cause: %+v\n%s", e, out)
			}
		case e.Cause != "" || e.Missing != nil:
			t.Fatalf("a %s skip carries a cause: %+v", e.Reason, e)
		}
	}
	if !strings.Contains(out, `"cause": "host_os"`) || !strings.Contains(out, `"missing": [`) {
		t.Fatalf("cause/missing not in the JSON:\n%s", out)
	}
}

func reasons(es []outcomeEntry) map[string]string {
	m := map[string]string{}
	for _, e := range es {
		m[e.ID] = e.Reason
	}
	return m
}

// #47 item 1: run -json -summary tells started from failed from skipped.
func TestRunJSONSummary(t *testing.T) {
	isolateHome(t)
	root := summaryTemplates(t)
	fe := summaryFake(t)
	code, out, errOut := run(t, fe, "-json", "-T", root, "run", "patched", "-t", "misc", "-summary", "-max-concurrent", "1",
		"-expose", "host", "-detach", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir())
	if code != ExitOK {
		t.Fatalf("run: %d\n%s\n%s", code, out, errOut)
	}
	var sum struct {
		Targets []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"targets"`
		Failed  []outcomeEntry `json:"failed"`
		Skipped []outcomeEntry `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(out), &sum); err != nil {
		t.Fatalf("stdout is not the summary: %v\n%s", err, out)
	}
	// With a cap of 1, aaa-ok starts and the rest that would run are over it.
	if len(sum.Targets) != 1 || sum.Targets[0].ID != "aaa-ok" || sum.Targets[0].State != "patched" || len(sum.Failed) != 0 {
		t.Fatalf("targets/failed: %s", out)
	}
	want := map[string]string{"bbb-windows-only": reasonRequires, "ccc-host-access": reasonHostAccess,
		"ddd-fails": reasonOverCap, "eee-ok": reasonOverCap, "fff-vuln-only": reasonNoState}
	if got := reasons(sum.Skipped); len(got) != len(want) {
		t.Fatalf("skipped = %v, want %v", got, want)
	} else {
		for id, r := range want {
			if got[id] != r {
				t.Fatalf("skipped[%s] = %q, want %q (%s)", id, got[id], r, out)
			}
		}
	}
	checkRequiresCause(t, sum.Skipped, out)

	// Without the cap: ddd-fails is a start failure, the run exits 1, and the
	// summary is still printed.
	fe = summaryFake(t)
	code, out, errOut = run(t, fe, "-json", "-T", root, "run", "-t", "misc", "-summary",
		"-expose", "host", "-detach", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir())
	if code != ExitFail {
		t.Fatalf("run with a start failure: %d\n%s\n%s", code, out, errOut)
	}
	sum.Targets, sum.Failed, sum.Skipped = nil, nil, nil
	if err := json.Unmarshal([]byte(out), &sum); err != nil {
		t.Fatalf("summary not printed on failure: %v\n%s", err, out)
	}
	if len(sum.Targets) != 3 || reasons(sum.Failed)["ddd-fails"] != reasonStart || len(sum.Failed) != 1 ||
		!strings.Contains(sum.Failed[0].Detail, "boom") || len(sum.Skipped) != 2 {
		t.Fatalf("summary: %s", out)
	}

	// Nothing comes up: the summary still says why.
	code, out, errOut = run(t, summaryFake(t), "-json", "-T", root, "run", "-t", "ccc-host-access", "-summary", "-detach")
	sum.Targets, sum.Failed, sum.Skipped = nil, nil, nil
	if code != ExitFail || json.Unmarshal([]byte(out), &sum) != nil || len(sum.Targets) != 0 ||
		reasons(sum.Skipped)["ccc-host-access"] != reasonHostAccess || !strings.Contains(out, `"targets": []`) {
		t.Fatalf("nothing came up: %d\n%s\n%s", code, out, errOut)
	}

	// Without -summary the -json output is still the bare handle array.
	code, out, errOut = run(t, summaryFake(t), "-json", "-T", root, "run", "-t", "aaa-ok",
		"-expose", "host", "-detach", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir())
	var handles []map[string]any
	if code != ExitOK || json.Unmarshal([]byte(out), &handles) != nil || len(handles) != 1 {
		t.Fatalf("bare -json: %d\n%s\n%s", code, out, errOut)
	}

	// -summary without -json is a usage error.
	if code, _, errOut := run(t, summaryFake(t), "-T", root, "run", "-t", "aaa-ok", "-summary"); code != ExitUsage || !strings.Contains(errOut, "add -json") {
		t.Fatalf("-summary without -json: %d %s", code, errOut)
	}
}

// #47 item 1: an interrupted run reports what it cancelled.
func TestRunJSONSummaryInterrupted(t *testing.T) {
	root := lifecycleTemplates(t, nil, "aaa1", "aaa2", "aaa3")
	fe := lifecycleFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serve := fe.StartFn
	fe.StartFn = func(spec engine.ContainerSpec) error {
		if spec.Name == "vulnsuite-aaa2-vulnerable" {
			cancel()
			return context.Canceled
		}
		return serve(spec)
	}
	var out, errOut bytes.Buffer
	code := mainWithEngine(ctx, fe, []string{"-json", "-T", root, "run", "-t", "misc", "-summary",
		"-expose", "host", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir()}, &out, &errOut)
	var sum runSummary
	if code == ExitOK || json.Unmarshal([]byte(out.String()), &sum) != nil {
		t.Fatalf("interrupted: %d\n%s\n%s", code, out.String(), errOut.String())
	}
	if len(sum.Targets) != 0 || len(sum.Failed) != 0 || len(sum.Skipped) != 3 {
		t.Fatalf("interrupted summary: %s", out.String())
	}
	for id, r := range reasons(sum.Skipped) {
		if r != reasonCancelled {
			t.Fatalf("%s: reason %q, want cancelled (%s)", id, r, out.String())
		}
	}
}

// #47 item 1: build -json -summary splits built / failed / skipped.
func TestBuildJSONSummary(t *testing.T) {
	isolateHome(t)
	root := summaryTemplates(t)
	fe := summaryFake(t)
	code, out, errOut := run(t, fe, "-json", "-T", root, "build", "-t", "misc", "-state", "patched", "-summary")
	if code != ExitOK {
		t.Fatalf("build: %d\n%s\n%s", code, out, errOut)
	}
	var sum buildSummary
	if err := json.Unmarshal([]byte(out), &sum); err != nil {
		t.Fatalf("stdout: %v\n%s", err, out)
	}
	if len(sum.Built) != 4 || len(sum.Failed) != 0 {
		t.Fatalf("built/failed: %s", out)
	}
	if got := reasons(sum.Skipped); len(got) != 2 || got["bbb-windows-only"] != reasonRequires || got["fff-vuln-only"] != reasonNoState {
		t.Fatalf("skipped: %v\n%s", got, out)
	}
	checkRequiresCause(t, sum.Skipped, out)

	fe = enginetest.New() // the image is not local, so it must be pulled
	fe.FailPull = true
	code, out, _ = run(t, fe, "-json", "-T", root, "build", "-t", "aaa-ok", "-summary")
	sum = buildSummary{}
	if code != ExitFail || json.Unmarshal([]byte(out), &sum) != nil || len(sum.Failed) != 2 || len(sum.Built) != 0 || sum.Failed[0].Error == "" {
		t.Fatalf("failed pulls: %d\n%s", code, out)
	}
}

// #47 item 1: jobs an interrupt stopped before they started are counted, in
// the text summary, the bare -json array and -summary alike.
func TestBuildCountsJobsCancelledBeforeStart(t *testing.T) {
	isolateHome(t)
	root := lifecycleTemplates(t, nil, "aaa1", "aaa2", "aaa3")
	interrupted := func() (*enginetest.Fake, context.Context) {
		fe := enginetest.New()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		fe.PullFn = func(string) error {
			cancel() // Ctrl-C during the first pull
			return context.Canceled
		}
		return fe, ctx
	}
	args := []string{"-T", root, "build", "-t", "misc", "-state", "vulnerable", "-j", "1"}

	fe, ctx := interrupted()
	var out, errOut bytes.Buffer
	code := mainWithEngine(ctx, fe, args, &out, &errOut)
	if code == ExitOK || !strings.Contains(out.String(), "cancelled before starting") || !strings.Contains(errOut.String(), "interrupted") {
		t.Fatalf("text: %d\n%s\n%s", code, out.String(), errOut.String())
	}

	fe, ctx = interrupted()
	out.Reset()
	errOut.Reset()
	code = mainWithEngine(ctx, fe, append([]string{"-json"}, args...), &out, &errOut)
	var res []buildResult
	if code == ExitOK || json.Unmarshal([]byte(out.String()), &res) != nil || len(res) != 3 {
		t.Fatalf("bare -json must list all 3 jobs: %d\n%s\n%s", code, out.String(), errOut.String())
	}
	cancelled := 0
	for _, r := range res {
		if r.Error == "" {
			t.Fatalf("no job succeeded, yet %s has no error: %s", r.ID, out.String())
		}
		if r.Error == "cancelled before it started" {
			cancelled++
		}
	}
	if cancelled == 0 {
		t.Fatalf("no job reported as cancelled before it started: %s", out.String())
	}

	fe, ctx = interrupted()
	out.Reset()
	errOut.Reset()
	code = mainWithEngine(ctx, fe, append([]string{"-json"}, append(args, "-summary")...), &out, &errOut)
	var sum buildSummary
	if code == ExitOK || json.Unmarshal([]byte(out.String()), &sum) != nil {
		t.Fatalf("-summary: %d\n%s\n%s", code, out.String(), errOut.String())
	}
	if len(sum.Built) != 0 || len(sum.Failed)+len(sum.Skipped) != 3 || len(sum.Skipped) != cancelledCount(sum.Skipped) || len(sum.Skipped) == 0 {
		t.Fatalf("-summary: %s", out.String())
	}
}

func cancelledCount(es []outcomeEntry) int {
	n := 0
	for _, e := range es {
		if e.Reason == reasonCancelled {
			n++
		}
	}
	return n
}
