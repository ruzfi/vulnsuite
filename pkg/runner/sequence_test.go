package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

const (
	seqID     = "seq-race-test"
	seqLogDir = "/var/log/asan"
)

// shortWindows shortens the executor's waits for a test.
func shortWindows(t *testing.T) {
	t.Helper()
	aw, ap, mf, es, ep := assertWindow, assertPoll, MaxFreezeWindow, exitSettle, exitPoll
	assertWindow, assertPoll, exitSettle, exitPoll = 150*time.Millisecond, 10*time.Millisecond, 50*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { assertWindow, assertPoll, MaxFreezeWindow, exitSettle, exitPoll = aw, ap, mf, es, ep })
}

// seqFix is a running target state with a "driver" sidecar on the fake
// engine, and the sequence executor for it.
type seqFix struct {
	t      *testing.T
	fe     *enginetest.Fake
	r      *Runner
	c      *contract.Contract
	h      *Handle
	target string
	driver string

	mu   sync.Mutex
	logs string
	// kills is every exec that killed a step left running.
	kills []string
	// onExec answers an exec of a trigger (anything but the in-container
	// healthcheck); nil = exit 0.
	onExec func(container, cmd string) (int, string, error)
}

func newSeqFix(t *testing.T) *seqFix {
	t.Helper()
	shortWindows(t)
	f := &seqFix{t: t, fe: enginetest.New()}
	f.c = &contract.Contract{
		APIVersion: contract.APIVersion,
		Kind:       "Target",
		Metadata:   contract.Metadata{ID: seqID},
		Base:       contract.Base{Kind: contract.BaseImage, Image: "example:latest"},
		Service: contract.Service{
			Ports:       []contract.Port{{Container: 7000, Protocol: "tcp"}},
			Healthcheck: contract.Healthcheck{Timeout: "2s"},
			Sidecars:    []contract.Sidecar{{Name: "driver", Image: "busybox:latest"}},
			Sanitizer:   &contract.Sanitizer{LogDir: seqLogDir},
		},
		States: map[string]*contract.State{"vulnerable": {Name: "vulnerable"}},
	}
	f.target = f.c.ContainerName("vulnerable")
	f.driver = SidecarContainerName(seqID, "vulnerable", "driver")
	ctx := context.Background()
	f.fe.Images["example:latest"] = true
	for _, name := range []string{f.target, f.driver} {
		if _, err := f.fe.ContainerCreate(ctx, engine.ContainerSpec{Name: name, Image: "example:latest"}); err != nil {
			t.Fatal(err)
		}
		if err := f.fe.ContainerStart(ctx, name); err != nil {
			t.Fatal(err)
		}
	}
	f.logDirMode(fs.ModeDir | fs.ModeSticky | 0o777)
	f.fe.LogsFn = func(engine.ContainerSpec) string {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.logs
	}
	f.fe.ExecFn = func(container, cmd string) (int, string, error) {
		if strings.Contains(cmd, "/proc/net/tcp") {
			return 0, "", nil // the in-container healthcheck: listening
		}
		if isStepKill(cmd) {
			f.mu.Lock()
			f.kills = append(f.kills, container+": "+cmd)
			f.mu.Unlock()
			return 0, "", nil
		}
		if orig, _, ok := untrackStepPID(cmd); ok {
			cmd = orig // a sequence exec step, as the template wrote it
		}
		f.mu.Lock()
		fn := f.onExec
		f.mu.Unlock()
		if fn != nil {
			return fn(container, cmd)
		}
		return 0, "", nil
	}
	f.r = unreachableRunner(f.fe)
	f.r.ExitPoll = 10 * time.Millisecond
	f.h = &Handle{ID: seqID, State: "vulnerable", Container: f.target, Exposure: DefaultExposure(), Ready: true,
		Sidecars: []string{f.driver}}
	return f
}

func (f *seqFix) logDirMode(mode fs.FileMode) {
	f.t.Helper()
	if err := f.fe.WriteFile(f.target, seqLogDir, mode, ""); err != nil {
		f.t.Fatal(err)
	}
}

func (f *seqFix) log(line string) {
	f.mu.Lock()
	f.logs += line + "\n"
	f.mu.Unlock()
}

// report writes a sanitizer report as the target's process pid would.
func (f *seqFix) report(pid int, text string) {
	f.t.Helper()
	if err := f.fe.WriteFile(f.target, fmt.Sprintf("%s/asan.%d", seqLogDir, pid), 0o644, text); err != nil {
		f.t.Error(err)
	}
}

func (f *seqFix) setExec(fn func(container, cmd string) (int, string, error)) {
	f.mu.Lock()
	f.onExec = fn
	f.mu.Unlock()
}

func (f *seqFix) exec() probes.ExecFunc {
	return func(ctx context.Context, container, command string, timeout time.Duration) (int, string, error) {
		return f.r.Engine.ContainerExec(ctx, container, command, timeout)
	}
}

// run runs s through probes.Run, as runProbes does.
func (f *seqFix) run(ctx context.Context, s *contract.SequenceProbe) probes.Result {
	f.t.Helper()
	return probes.Run(ctx, contract.Probe{Sequence: s}, probes.Target{Container: f.target, Exec: f.exec(),
		Sequence: f.r.sequenceFunc(f.c, f.c.States[f.h.State], f.h, f.exec())})
}

// calls is the fake's pause/exec/unpause log without healthcheck execs.
func (f *seqFix) calls() []string {
	var out []string
	for _, c := range f.fe.Calls {
		if strings.Contains(c, "/proc/net/tcp") || isStepKill(c) {
			continue
		}
		if prefix, cmd, ok := strings.Cut(c, ": "); ok {
			if orig, _, ok := untrackStepPID(cmd); ok {
				c = prefix + ": " + orig
			}
		}
		out = append(out, c)
	}
	return out
}

// assertThawed checks every pause of the target is followed by its unpause
// before anything else is paused, and that it ends unpaused.
func (f *seqFix) assertThawed() {
	f.t.Helper()
	paused := false
	for _, c := range f.fe.Calls {
		switch c {
		case "pause " + f.target:
			if paused {
				f.t.Errorf("paused twice without an unpause: %q", f.fe.Calls)
			}
			paused = true
		case "unpause " + f.target:
			if !paused {
				f.t.Errorf("unpause without a pause: %q", f.fe.Calls)
			}
			paused = false
		}
		if strings.HasPrefix(c, "pause ") && c != "pause "+f.target {
			f.t.Errorf("paused something other than the target: %q", c)
		}
	}
	if paused {
		f.t.Errorf("the target was left paused: %q", f.fe.Calls)
	}
	if c := f.fe.Containers[f.target]; c != nil && c.Paused {
		f.t.Error("the fake still has the target paused")
	}
}

// isStepKill reports whether cmd (or an exec call) is killStep's.
func isStepKill(cmd string) bool {
	return strings.Contains(cmd, `read -r p g < '/tmp/.vulnsuite-step-`)
}

func execStep(container, run string) contract.SequenceStep {
	return contract.SequenceStep{Exec: &contract.SequenceExec{ExecProbe: contract.ExecProbe{Run: run}, Container: container}}
}

func freeze() contract.SequenceStep { return contract.SequenceStep{Freeze: &contract.FreezeStep{}} }
func resume() contract.SequenceStep { return contract.SequenceStep{Resume: &contract.ResumeStep{}} }
func sleepMS(ms int) contract.SequenceStep {
	return contract.SequenceStep{Sleep: &contract.SleepStep{MS: ms}}
}
func expectHit(kind, frame string) contract.SequenceStep {
	return contract.SequenceStep{ExpectSanitizer: &contract.ExpectSanitizer{Kind: kind, Frame: frame}}
}
func expectNone() contract.SequenceStep {
	return contract.SequenceStep{ExpectSanitizer: &contract.ExpectSanitizer{None: true}}
}
func expectLog(pat string) contract.SequenceStep { return contract.SequenceStep{ExpectLog: &pat} }

// raceSteps is the resolver shape: setup and fire from the driver around a
// freeze, then the assertions.
func raceSteps(asserts ...contract.SequenceStep) []contract.SequenceStep {
	return append([]contract.SequenceStep{
		execStep("driver", "/trigger setup"), freeze(), execStep("driver", "/trigger fire"), resume(),
	}, asserts...)
}

func outcomes(r probes.Result) string {
	var o []string
	for _, a := range r.Attempts {
		o = append(o, a.Outcome)
	}
	return strings.Join(o, ",")
}

// The vulnerable resolver case: the driver fires while the target is frozen,
// the report appears after resume, and the first attempt hits.
func TestSequenceHit(t *testing.T) {
	f := newSeqFix(t)
	f.setExec(func(container, cmd string) (int, string, error) {
		if cmd == "/trigger fire" {
			f.report(12, asanResolverUAF)
		}
		return 0, "", nil
	})
	r := f.run(context.Background(), &contract.SequenceProbe{Attempts: 3, Steps: raceSteps(expectHit("heap-use-after-free", "ngx_resolver_process_a"))})
	if !r.OK || r.Kind != "sequence" || outcomes(r) != "hit" {
		t.Fatalf("result %+v", r)
	}
	want := "sequence: 1/1 hits (min 1): #1 hit: heap-use-after-free at ngx_resolver_process_a ngx_resolver.c:2142"
	if r.Detail != want {
		t.Fatalf("detail %q\nwant   %q", r.Detail, want)
	}
	// The fire ran in the sidecar while the target was frozen; nothing ran
	// in the target.
	wantCalls := []string{
		"exec " + f.driver + ": /trigger setup",
		"pause " + f.target,
		"exec " + f.driver + ": /trigger fire",
		"unpause " + f.target,
	}
	if got := f.calls(); strings.Join(got, "|") != strings.Join(wantCalls, "|") {
		t.Fatalf("calls %q\nwant  %q", got, wantCalls)
	}
	f.assertThawed()
	// A report from an earlier attempt (still in log_dir) is not new.
	f.setExec(nil)
	r = f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectHit("heap-use-after-free", ""))})
	if r.OK || outcomes(r) != "fail" || !strings.Contains(r.Detail, "#1 fail: no sanitizer report (want heap-use-after-free report)") {
		t.Fatalf("an old report counted: %+v", r)
	}
}

// Positive sequences: pass once min_hits attempts hit, fail as soon as that
// can no longer happen; not-reached attempts count toward neither.
func TestSequencePositiveDecision(t *testing.T) {
	for _, tc := range []struct {
		name             string
		attempts, min    int
		script           []string // per attempt: hit | fail | other | nr (setup fails)
		ok               bool
		outcomes, detail string
	}{
		{"first hit decides", 3, 1, []string{"hit"}, true, "hit", "sequence: 1/1 hits (min 1)"},
		{"hit after a miss", 3, 1, []string{"fail", "hit"}, true, "fail,hit", "#1 fail: no sanitizer report"},
		{"never hits", 3, 1, []string{"fail", "fail", "fail"}, false, "fail,fail,fail", "sequence: 0/3 hits (min 1)"},
		{"wrong kind is a fail", 1, 1, []string{"other"}, false, "fail", "reports: heap-buffer-overflow at copy_header"},
		{"two of three", 3, 2, []string{"hit", "fail", "hit"}, true, "hit,fail,hit", "sequence: 2/3 hits (min 2)"},
		{"stops once impossible", 3, 2, []string{"fail", "fail", "hit"}, false, "fail,fail", "sequence: 0/2 hits (min 2)"},
		{"not reached counts toward neither", 3, 1, []string{"nr", "hit"}, true, "not_reached,hit", `#1 not reached: driver: exec "/trigger setup" -> exit 1 != 0`},
		{"all not reached", 2, 1, []string{"nr", "nr"}, false, "not_reached,not_reached",
			`sequence: no attempt reached the race (2/2 not reached), last: driver: exec "/trigger setup" -> exit 1 != 0`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSeqFix(t)
			attempt, pid := 0, 100
			f.setExec(func(container, cmd string) (int, string, error) {
				switch cmd {
				case "/trigger setup":
					attempt++
					if tc.script[attempt-1] == "nr" {
						return 1, "", nil
					}
				case "/trigger fire":
					pid++
					switch tc.script[attempt-1] {
					case "hit":
						f.report(pid, asanResolverUAF)
					case "other":
						f.report(pid, clangOverflow)
					}
				}
				return 0, "", nil
			})
			r := f.run(context.Background(), &contract.SequenceProbe{Attempts: tc.attempts, MinHits: tc.min,
				Steps: raceSteps(expectHit("heap-use-after-free", "ngx_resolver"))})
			if r.OK != tc.ok || outcomes(r) != tc.outcomes || !strings.Contains(r.Detail, tc.detail) {
				t.Fatalf("ok %v outcomes %s detail %q; want %v %s ~ %q", r.OK, outcomes(r), r.Detail, tc.ok, tc.outcomes, tc.detail)
			}
			f.assertThawed()
		})
	}
}

// A frame that is only in the free or allocation stack does not hit.
func TestSequenceFrameMustBeInFirstStack(t *testing.T) {
	f := newSeqFix(t)
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger fire" {
			f.report(12, asanResolverUAF)
		}
		return 0, "", nil
	})
	r := f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectHit("heap-use-after-free", "ngx_resolve_name_done"))})
	want := "#1 fail: no heap-use-after-free report with a frame ~ /ngx_resolve_name_done/; reports: heap-use-after-free at ngx_resolver_process_a ngx_resolver.c:2142"
	if r.OK || !strings.HasSuffix(r.Detail, want) {
		t.Fatalf("detail %q", r.Detail)
	}
}

// The report may appear a little after resume (it is written and symbolized
// then): a positive expect_sanitizer waits for it within its window.
func TestSequenceWaitsForLateReport(t *testing.T) {
	f := newSeqFix(t)
	assertWindow = 2 * time.Second
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger fire" {
			time.AfterFunc(200*time.Millisecond, func() { f.report(12, asanResolverUAF) })
		}
		return 0, "", nil
	})
	start := time.Now()
	r := f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectHit("heap-use-after-free", ""))})
	if !r.OK || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("after %v: %+v", time.Since(start), r)
	}
}

// Patched (`none`) sequences: a report in any attempt fails, the first clean
// attempt passes, and not-reached attempts only absorb harness errors.
func TestSequenceNoneDecision(t *testing.T) {
	const positive = `writev\(\) failed .* while sending to client`
	for _, tc := range []struct {
		name             string
		attempts         int
		script           []string // per attempt: clean | report | nr (setup fails) | nolog (race not reached) | report-nolog
		ok               bool
		outcomes, detail string
	}{
		{"clean pass decides", 3, []string{"clean"}, true, "pass",
			`sequence: 1/1 passed, 0 failed: #1 pass: no sanitizer report; log ~ /` + positive + `/`},
		{"report fails at once", 3, []string{"report"}, false, "fail", "#1 fail: sanitizer report: heap-use-after-free at ngx_resolver_process_a ngx_resolver.c:2142"},
		{"harness error then pass", 3, []string{"nr", "clean"}, true, "not_reached,pass", "sequence: 1/2 passed, 0 failed"},
		{"report after a harness error", 3, []string{"nr", "report"}, false, "not_reached,fail", "sequence: 0/2 passed, 1 failed"},
		{"positive control missing", 2, []string{"nolog", "nolog"}, false, "not_reached,not_reached",
			"no attempt reached the race (2/2 not reached), last: the log written during the attempt (0 bytes) !~ /" + positive + "/"},
		{"a report is decisive without the positive control", 3, []string{"report-nolog"}, false, "fail", "#1 fail: sanitizer report"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSeqFix(t)
			f.log("nginx: start worker processes") // before the attempt: never matched
			attempt := 0
			f.setExec(func(_, cmd string) (int, string, error) {
				switch cmd {
				case "/trigger setup":
					attempt++
					if tc.script[attempt-1] == "nr" {
						return 1, "", nil
					}
				case "/trigger fire":
					s := tc.script[attempt-1]
					if strings.HasPrefix(s, "report") {
						f.report(attempt, asanResolverUAF)
					}
					if s == "clean" || s == "report" {
						f.log("2026/11/20 [info] writev() failed (32: Broken pipe) while sending to client")
					}
				}
				return 0, "", nil
			})
			r := f.run(context.Background(), &contract.SequenceProbe{Attempts: tc.attempts, Steps: raceSteps(expectNone(), expectLog(positive))})
			if r.OK != tc.ok || outcomes(r) != tc.outcomes || !strings.Contains(r.Detail, tc.detail) {
				t.Fatalf("ok %v outcomes %s detail %q; want %v %s ~ %q", r.OK, outcomes(r), r.Detail, tc.ok, tc.outcomes, tc.detail)
			}
			f.assertThawed()
		})
	}
}

// expect_log matches only what was logged during the attempt.
func TestSequenceExpectLogOnlyThisAttempt(t *testing.T) {
	f := newSeqFix(t)
	f.log("writev() failed while sending to client") // an earlier run's line
	r := f.run(context.Background(), &contract.SequenceProbe{Steps: []contract.SequenceStep{
		execStep("", "/bin/true"), expectLog("writev"),
	}})
	if r.OK || outcomes(r) != "not_reached" {
		t.Fatalf("an old log line counted: %+v", r)
	}
	f.setExec(func(_, cmd string) (int, string, error) {
		f.log("writev() failed again")
		return 0, "", nil
	})
	r = f.run(context.Background(), &contract.SequenceProbe{Steps: []contract.SequenceStep{
		execStep("", "/bin/true"), expectLog("again"),
	}})
	if !r.OK || outcomes(r) != "pass" {
		t.Fatalf("%+v", r)
	}
}

// An exec step without container runs in the target; with expect_exit and
// stdout_matches it asserts like an exec probe.
func TestSequenceExecAssertions(t *testing.T) {
	f := newSeqFix(t)
	f.c.Service.Sanitizer = nil
	f.setExec(func(container, cmd string) (int, string, error) {
		if container != f.target {
			t.Errorf("ran in %s", container)
		}
		return 3, "state=armed\n", nil
	})
	three := 3
	r := f.run(context.Background(), &contract.SequenceProbe{Steps: []contract.SequenceStep{
		{Exec: &contract.SequenceExec{ExecProbe: contract.ExecProbe{Run: "check", ExpectExit: &three, StdoutMatches: "armed"}}},
	}})
	if !r.OK || r.Detail != `sequence: 1/1 passed, 0 failed: #1 pass: exec "check" -> ok` {
		t.Fatalf("%+v", r)
	}
	r = f.run(context.Background(), &contract.SequenceProbe{Steps: []contract.SequenceStep{
		{Exec: &contract.SequenceExec{ExecProbe: contract.ExecProbe{Run: "check", StdoutMatches: "fired"}}},
	}})
	if r.OK || !strings.Contains(r.Detail, `#1 not reached: exec "check" -> exit 3 != 0; stdout !~ /fired/`) {
		t.Fatalf("%+v", r)
	}
}

// Every way an attempt can end while the target is frozen thaws it.
func TestSequenceFreezeGuarantees(t *testing.T) {
	for _, tc := range []struct {
		name    string
		steps   []contract.SequenceStep
		timeout float64
		cancel  time.Duration // cancel the run after this long (0 = never)
		exec    func(cmd string) (int, string, error)
		detail  string
		fast    bool // must end well before the frozen sleep would
	}{
		{name: "exec error while frozen", steps: raceSteps(expectHit("heap-use-after-free", "")),
			exec: func(cmd string) (int, string, error) {
				if cmd == "/trigger fire" {
					return -1, "", errors.New("driver went away")
				}
				return 0, "", nil
			},
			detail: `#1 not reached: driver: exec "/trigger fire" -> driver went away`},
		{name: "failing exec while frozen", steps: raceSteps(expectHit("heap-use-after-free", "")),
			exec: func(cmd string) (int, string, error) {
				if cmd == "/trigger fire" {
					return 2, "", nil
				}
				return 0, "", nil
			},
			detail: `#1 not reached: driver: exec "/trigger fire" -> exit 2 != 0`},
		{name: "attempt timeout while frozen", timeout: 0.2, fast: true,
			steps:  []contract.SequenceStep{freeze(), sleepMS(5000), resume(), expectHit("heap-use-after-free", "")},
			detail: "#1 not reached: timed out after 200ms at step 2 (sleep)"},
		{name: "cancel while frozen", cancel: 200 * time.Millisecond, fast: true,
			steps:  []contract.SequenceStep{freeze(), sleepMS(5000), resume(), expectHit("heap-use-after-free", "")},
			detail: "#1 not reached: cancelled at step 2 (sleep)"},
		{name: "freeze window cap", fast: true,
			steps:  []contract.SequenceStep{freeze(), sleepMS(5000), resume(), expectHit("heap-use-after-free", "")},
			detail: "#1 not reached: the target stayed frozen longer than 200ms (step 2, sleep); it was unpaused"},
		{name: "freeze cap during a sidecar exec", fast: true,
			steps: raceSteps(expectHit("heap-use-after-free", "")),
			exec: func(cmd string) (int, string, error) {
				if cmd == "/trigger fire" {
					time.Sleep(400 * time.Millisecond) // the fake's exec ignores ctx
				}
				return 0, "", nil
			},
			detail: "#1 not reached: the target stayed frozen longer than 200ms (step 3, exec); it was unpaused"},
		{name: "no resume", steps: []contract.SequenceStep{freeze(), execStep("driver", "/trigger fire")},
			exec: func(cmd string) (int, string, error) { return 0, "", nil },
			// No assertion fails, so the attempt passes, and the target is
			// thawed at its end anyway.
			detail: "#1 pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSeqFix(t)
			MaxFreezeWindow = 200 * time.Millisecond
			if tc.exec != nil {
				f.setExec(func(_, cmd string) (int, string, error) { return tc.exec(cmd) })
			}
			ctx := context.Background()
			if tc.cancel > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				time.AfterFunc(tc.cancel, cancel)
				defer cancel()
			}
			if tc.name != "freeze window cap" && tc.name != "freeze cap during a sidecar exec" {
				MaxFreezeWindow = 30 * time.Second
			}
			start := time.Now()
			r := f.run(ctx, &contract.SequenceProbe{Attempts: 1, Timeout: tc.timeout, Steps: tc.steps})
			if !strings.Contains(r.Detail, tc.detail) {
				t.Fatalf("detail %q lacks %q", r.Detail, tc.detail)
			}
			if tc.fast && time.Since(start) > 2*time.Second {
				t.Fatalf("took %v", time.Since(start))
			}
			if !strings.Contains(strings.Join(f.calls(), "|"), "pause "+f.target) {
				t.Fatalf("never froze: %q", f.calls())
			}
			f.assertThawed()
		})
	}
}

// The freeze cap thaws the target even while a step is stuck, not only once
// it returns.
func TestSequenceFreezeCapThawsDuringStuckStep(t *testing.T) {
	f := newSeqFix(t)
	MaxFreezeWindow = 100 * time.Millisecond
	thawedDuringExec := make(chan bool, 1)
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger fire" {
			time.Sleep(400 * time.Millisecond)
			thawedDuringExec <- !f.paused()
		}
		return 0, "", nil
	})
	f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectHit("heap-use-after-free", ""))})
	if !<-thawedDuringExec {
		t.Fatal("the target was still frozen 400ms into a 100ms freeze window")
	}
	f.assertThawed()
}

func (f *seqFix) paused() bool {
	rows, _ := f.fe.ContainerList(context.Background(), true, f.target)
	return len(rows) == 1 && rows[0].State == "paused"
}

// A target that exits during an attempt (halt_on_error=1) is started again
// and waited for before the next one.
func TestSequenceRestartsExitedTarget(t *testing.T) {
	f := newSeqFix(t)
	pid := 0
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger crash" {
			// The thawed process hits the bug and aborts (halt_on_error=1).
			pid++
			f.report(pid, asanResolverUAF)
			f.fe.Exit(f.target, 1)
		}
		return 0, "", nil
	})
	r := f.run(context.Background(), &contract.SequenceProbe{Attempts: 3, MinHits: 2,
		Steps: raceSteps(execStep("driver", "/trigger crash"), expectHit("heap-use-after-free", "ngx_resolver_process_a"))})
	if !r.OK || outcomes(r) != "hit,hit" || !r.Attempts[1].Restarted || r.Attempts[0].Restarted {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.Detail, "sequence: 2/2 hits (min 2): #1 hit: heap-use-after-free at ngx_resolver_process_a ngx_resolver.c:2142; #2 (target restarted) hit:") {
		t.Fatalf("detail %q", r.Detail)
	}
	if !f.h.Ready {
		t.Fatal("handle not ready after the restart")
	}
}

// A target that cannot be started again makes the remaining attempts not
// reached.
func TestSequenceRestartFails(t *testing.T) {
	f := newSeqFix(t)
	f.fe.StartFn = func(engine.ContainerSpec) error { return errors.New("port is already allocated") }
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger crash" {
			f.fe.Exit(f.target, 1)
		}
		return 0, "", nil
	})
	r := f.run(context.Background(), &contract.SequenceProbe{Attempts: 3,
		Steps: raceSteps(execStep("driver", "/trigger crash"), expectHit("heap-use-after-free", ""))})
	if r.OK || outcomes(r) != "fail,not_reached,not_reached" ||
		!strings.Contains(r.Detail, "#2 not reached: the target exited with code 1 and could not be started again: port is already allocated") {
		t.Fatalf("%+v", r)
	}
}

// The log_dir must exist and be writable by every user before any attempt.
func TestSequenceLogDirCheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   fs.FileMode
		absent bool
		detail string
	}{
		{name: "sticky 1777", mode: fs.ModeDir | fs.ModeSticky | 0o777},
		{name: "0777", mode: fs.ModeDir | 0o777},
		{name: "0755", mode: fs.ModeDir | 0o755, detail: "sequence: sanitizer log_dir /var/log/asan is not writable by every user (mode 0755)"},
		{name: "sticky 1775", mode: fs.ModeDir | fs.ModeSticky | 0o775, detail: "sequence: sanitizer log_dir /var/log/asan is not writable by every user (mode 1775)"},
		{name: "a file", mode: 0o777, detail: "sequence: sanitizer log_dir /var/log/asan is not a directory (mode -rwxrwxrwx)"},
		{name: "missing", absent: true, detail: "sequence: sanitizer log_dir /var/log/asan does not exist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSeqFix(t)
			if tc.absent {
				delete(f.fe.Containers[f.target].Files, seqLogDir)
			} else {
				f.logDirMode(tc.mode)
			}
			r := f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectNone())})
			if tc.detail == "" {
				if !r.OK {
					t.Fatalf("%+v", r)
				}
				return
			}
			if r.OK || r.Detail != tc.detail || len(r.Attempts) != 0 || len(f.calls()) != 0 {
				t.Fatalf("result %+v, calls %q; want %q before any step", r, f.calls(), tc.detail)
			}
		})
	}
}

// pauseless and fileless hide one optional interface of the fake.
type pauseless struct {
	engine.Engine
	engine.FileReader
}

type fileless struct {
	engine.Engine
	engine.Pauser
}

// An engine without pause or archive reads fails verify clearly; the
// sequence is not skipped.
func TestSequenceEngineCapabilities(t *testing.T) {
	f := newSeqFix(t)
	f.r.Engine = pauseless{f.fe, f.fe}
	r := f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectNone())})
	if r.OK || r.Detail != "sequence: this engine cannot pause containers, so freeze cannot run" {
		t.Fatalf("%+v", r)
	}
	// Without freeze the pauseless engine runs it.
	r = f.run(context.Background(), &contract.SequenceProbe{Steps: []contract.SequenceStep{execStep("driver", "go"), expectNone()}})
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	f.r.Engine = fileless{f.fe, f.fe}
	r = f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectNone())})
	if r.OK || r.Detail != "sequence: sanitizer log_dir /var/log/asan: this engine cannot read files from containers" {
		t.Fatalf("%+v", r)
	}
	if len(f.calls()) != 1 { // only the pauseless run's exec
		t.Fatalf("calls %q", f.calls())
	}
}

// Network steps run against the target the runner already probes; from a
// machine that cannot reach it the attempt is not reached, with the reason.
func TestSequenceNetworkStepUnreachable(t *testing.T) {
	f := newSeqFix(t)
	r := f.run(context.Background(), &contract.SequenceProbe{Steps: []contract.SequenceStep{
		{TCP: &contract.TCPProbe{Port: 7000}}, execStep("driver", "go"), expectNone(),
	}})
	if r.OK || !strings.Contains(r.Detail, "no attempt reached the race (1/1 not reached), last: tcp step 1 cannot run: could not verify from this host in internal mode") {
		t.Fatalf("%+v", r)
	}
}

func sequenceContract(verify ...contract.Probe) *contract.Contract {
	return &contract.Contract{
		APIVersion: contract.APIVersion,
		Kind:       "Target",
		Metadata:   contract.Metadata{ID: seqID},
		Base:       contract.Base{Kind: contract.BaseImage, Image: "example:latest"},
		Service: contract.Service{
			Ports:     []contract.Port{{Container: 8080, Protocol: "http"}},
			Sidecars:  []contract.Sidecar{{Name: "driver", Image: "busybox:latest"}},
			Sanitizer: &contract.Sanitizer{LogDir: seqLogDir},
		},
		States: map[string]*contract.State{"vulnerable": {Name: "vulnerable", Verify: verify}},
	}
}

// The key goal: a sequence without network steps verifies in internal mode
// on a host that cannot reach the target (Docker Desktop, OrbStack). Next to
// a network probe the result is partial, as for exec probes.
func TestRunSequenceUnreachable(t *testing.T) {
	shortWindows(t)
	seq := contract.Probe{Sequence: &contract.SequenceProbe{Steps: raceSteps(expectHit("heap-use-after-free", "ngx_resolver"))}}
	tcp := contract.Probe{TCP: &contract.TCPProbe{Port: 8080}}
	for name, tc := range map[string]struct {
		verify []contract.Probe
		ok     any
		detail []string
	}{
		"sequence only":        {[]contract.Probe{seq}, true, []string{"ok   sequence: 1/1 hits (min 1): #1 hit: heap-use-after-free at ngx_resolver_process_a"}},
		"sequence and network": {[]contract.Probe{seq, tcp}, nil, []string{"ok   sequence: 1/1 hits", "skip 1 network probe(s)"}},
	} {
		t.Run(name, func(t *testing.T) {
			fe := enginetest.New()
			target := contract.ContainerName(seqID, "vulnerable")
			fe.StartFn = func(spec engine.ContainerSpec) error {
				if spec.Name == target {
					return fe.WriteFile(target, seqLogDir, fs.ModeDir|fs.ModeSticky|0o777, "")
				}
				return nil
			}
			fe.ExecFn = func(_, cmd string) (int, string, error) {
				if orig, _, ok := untrackStepPID(cmd); ok {
					cmd = orig
				}
				if cmd == "/trigger fire" {
					_ = fe.WriteFile(target, seqLogDir+"/asan.7", 0o644, asanResolverUAF)
				}
				return 0, "", nil
			}
			h, err := unreachableRunner(fe).Run(context.Background(), sequenceContract(tc.verify...), "vulnerable", DefaultExposure(),
				Options{Verify: true, Build: builder.Options{Pull: true}})
			if err != nil {
				t.Fatal(err)
			}
			if deref(h.VerifyOK) != tc.ok {
				t.Fatalf("VerifyOK = %v, want %v; detail %q", deref(h.VerifyOK), tc.ok, h.VerifyDetail)
			}
			for _, d := range tc.detail {
				if !strings.Contains(h.VerifyDetail, d) {
					t.Errorf("detail %q lacks %q", h.VerifyDetail, d)
				}
			}
			if len(h.Probes) != 1 || len(h.Probes[0].Attempts) != 1 || h.Probes[0].Attempts[0].Outcome != probes.OutcomeHit {
				t.Fatalf("probes %+v", h.Probes)
			}
		})
	}
}

// On a reachable target a sequence runs its network steps against the same
// address the other probes use, and per-attempt results appear in -json
// only as the new attempts field.
func TestRunSequenceReachable(t *testing.T) {
	shortWindows(t)
	fe := enginetest.New()
	target := contract.ContainerName(seqID, "vulnerable")
	fe.StartFn = func(spec engine.ContainerSpec) error {
		if spec.Name == target {
			if err := fe.WriteFile(target, seqLogDir, fs.ModeDir|fs.ModeSticky|0o777, ""); err != nil {
				return err
			}
		}
		for _, p := range spec.Ports {
			l, err := net.Listen("tcp", net.JoinHostPort(p.HostIP, strconv.Itoa(p.HostPort)))
			if err != nil {
				return err
			}
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ready") }))
			srv.Listener.Close()
			srv.Listener = l
			srv.Config.ErrorLog = log.New(io.Discard, "", 0)
			srv.Start()
			t.Cleanup(srv.Close)
		}
		return nil
	}
	status := 200
	c := sequenceContract(
		contract.Probe{HTTP: &contract.HTTPProbe{Status: &status, BodyMatches: "ready"}},
		contract.Probe{Sequence: &contract.SequenceProbe{Steps: []contract.SequenceStep{
			{HTTP: &contract.HTTPProbe{Path: "/", Status: &status, BodyMatches: "ready"}},
			execStep("driver", "/trigger fire"),
			expectNone(),
		}}},
	)
	h, err := New(fe).Run(context.Background(), c, "vulnerable", Exposure{Mode: ModeHost, Bind: "127.0.0.1"},
		Options{Verify: true, ReadyTimeout: 3 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.VerifyOK == nil || !*h.VerifyOK {
		t.Fatalf("VerifyOK = %v; detail %q", deref(h.VerifyOK), h.VerifyDetail)
	}
	if !strings.Contains(h.VerifyDetail, "ok   / -> 200, ok\nok   sequence: 1/1 passed, 0 failed: #1 pass: no sanitizer report") {
		t.Fatalf("detail %q", h.VerifyDetail)
	}
	b, err := json.Marshal(h.Probes)
	if err != nil {
		t.Fatal(err)
	}
	var raw []map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw[0]["attempts"]; ok {
		t.Errorf("an http probe has attempts: %s", b)
	}
	att, ok := raw[1]["attempts"].([]any)
	if !ok || len(att) != 1 {
		t.Fatalf("sequence attempts in json: %s", b)
	}
	a := att[0].(map[string]any)
	if a["attempt"] != 1.0 || a["outcome"] != "pass" || a["detail"] != "no sanitizer report" {
		t.Fatalf("attempt json %v", a)
	}
}

// stop (StopAll, and Stop for one handle) removes a paused target: dockerd's
// force remove takes a paused container (#124's conformance and e2e cases),
// so no unpause is needed first.
func TestStopRemovesPausedTarget(t *testing.T) {
	f := newSeqFix(t)
	for _, name := range []string{f.target, f.driver} {
		f.fe.Containers[name].Spec.Labels = map[string]string{LabelManaged: "true", LabelRole: RoleTarget,
			builder.LabelID: seqID, builder.LabelState: "vulnerable"}
	}
	f.fe.Containers[f.driver].Spec.Labels[LabelRole] = RoleSidecar
	if err := f.fe.ContainerPause(context.Background(), f.target); err != nil {
		t.Fatal(err)
	}
	names, err := f.r.StopAll(context.Background(), seqID)
	if err != nil || len(names) != 2 {
		t.Fatalf("StopAll = %v, %v", names, err)
	}
	if len(f.fe.Containers) != 0 {
		t.Fatalf("left %v", f.fe.Containers)
	}
	// Stop on a handle too.
	g := newSeqFix(t)
	if err := g.fe.ContainerPause(context.Background(), g.target); err != nil {
		t.Fatal(err)
	}
	if err := g.r.Stop(context.Background(), g.h); err != nil || len(g.fe.Containers) != 0 {
		t.Fatalf("Stop = %v, left %v", err, g.fe.Containers)
	}
}

// A restarted PID-1 target rewrites the same asan.<pid> file, often with the
// same size and even the same text: that is a new report. A report appended
// to an existing file is read without the file's older reports.
func TestSequenceRewrittenAndAppendedReports(t *testing.T) {
	f := newSeqFix(t)
	f.report(1, asanResolverUAF) // from an earlier attempt
	time.Sleep(2 * time.Millisecond)
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger fire" {
			f.report(1, asanResolverUAF) // byte for byte the same
		}
		return 0, "", nil
	})
	r := f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectHit("heap-use-after-free", "ngx_resolver_process_a"))})
	if !r.OK {
		t.Fatalf("a rewritten report was missed: %+v", r)
	}

	g := newSeqFix(t)
	g.report(2, clangOverflow)
	g.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger fire" {
			g.report(2, clangOverflow+segv)
		}
		return 0, "", nil
	})
	r = g.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectHit("heap-buffer-overflow", ""))})
	if r.OK || !strings.HasSuffix(r.Detail, "#1 fail: no heap-buffer-overflow report; reports: SEGV at deref x.c:5") {
		t.Fatalf("the old part of an appended file was read again: %+v", r)
	}
}
