package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// #136 item 1: a step that stops the attempt before expect_sanitizer: none
// runs (the target aborted with a report, so a check exec fails) must not
// hide the report: the attempt fails, and a clean later attempt does not
// turn the patched verify into a pass.
func TestSequenceNoneFailsWhenAnEarlierStepStops(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check contract.SequenceStep
	}{
		{"exec", execStep("driver", "/trigger check")},
		{"expect_log", expectLog("request served")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSeqFix(t)
			attempt := 0
			f.setExec(func(_, cmd string) (int, string, error) {
				switch cmd {
				case "/trigger setup":
					attempt++
				case "/trigger fire":
					if attempt == 1 {
						f.report(attempt, asanResolverUAF)
					} else {
						f.log("request served")
					}
				case "/trigger check":
					if attempt == 1 {
						return 1, "", nil
					}
				}
				return 0, "", nil
			})
			r := f.run(context.Background(), &contract.SequenceProbe{Attempts: 3, Steps: raceSteps(tc.check, expectNone())})
			if r.OK || outcomes(r) != "fail" {
				t.Fatalf("outcomes %s: %+v", outcomes(r), r)
			}
			if !strings.Contains(r.Detail, "sanitizer report: heap-use-after-free") || !strings.Contains(r.Detail, "the attempt stopped early") {
				t.Errorf("detail %q", r.Detail)
			}
		})
	}
}

// Without a report, an attempt stopped early stays not reached.
func TestSequenceNoneEarlyStopWithoutReportIsNotReached(t *testing.T) {
	f := newSeqFix(t)
	attempt := 0
	f.setExec(func(_, cmd string) (int, string, error) {
		switch cmd {
		case "/trigger setup":
			attempt++
		case "/trigger check":
			if attempt == 1 {
				return 1, "", nil
			}
		}
		return 0, "", nil
	})
	r := f.run(context.Background(), &contract.SequenceProbe{Attempts: 3, Steps: raceSteps(execStep("driver", "/trigger check"), expectNone())})
	if !r.OK || outcomes(r) != "not_reached,pass" {
		t.Fatalf("outcomes %s: %+v", outcomes(r), r)
	}
}

// A ThreadSanitizer report (WARNING header) fails expect_sanitizer: none and
// hits a positive data-race step.
func TestSequenceThreadSanitizer(t *testing.T) {
	const tsan = "==================\nWARNING: ThreadSanitizer: data race (pid=7)\n  Write of size 4 at 0x7b04 by thread T2:\n    #0 worker /src/race.c:12:5 (race+0x1234)\n\nSUMMARY: ThreadSanitizer: data race /src/race.c:12:5 in worker\n"
	fix := func() *seqFix {
		f := newSeqFix(t)
		f.setExec(func(_, cmd string) (int, string, error) {
			if cmd == "/trigger fire" {
				f.report(7, tsan)
			}
			return 0, "", nil
		})
		return f
	}
	if r := fix().run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectNone())}); r.OK || outcomes(r) != "fail" {
		t.Fatalf("none: %+v", r)
	}
	r := fix().run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectHit("data-race", "worker"))})
	if !r.OK || outcomes(r) != "hit" || !strings.Contains(r.Detail, "data-race at worker race.c:12:5") {
		t.Fatalf("hit: %+v", r)
	}
}

// #136 items 5 and 7: a target restarted between attempts gets Run's
// readiness timeout and its seed steps again; a seed that fails then is
// noted, not fatal.
func TestSequenceRestartUsesReadyTimeoutAndReseeds(t *testing.T) {
	f := newSeqFix(t)
	f.c.Service.Healthcheck.Timeout = "1s"
	f.h.readyTimeout = 5 * time.Second
	f.c.States["vulnerable"].Seed = []contract.SeedStep{{Run: "/seed users"}, {Run: "/seed data"}}
	var mu sync.Mutex
	var notListeningUntil time.Time
	seeds := 0
	failSeed := false
	health := f.fe.ExecFn
	f.fe.ExecFn = func(container, cmd string) (int, string, error) {
		if strings.Contains(cmd, "/proc/net/tcp") {
			mu.Lock()
			wait := time.Now().Before(notListeningUntil)
			mu.Unlock()
			if wait {
				return 1, "", nil // still booting
			}
		}
		if strings.HasPrefix(cmd, "/seed ") {
			mu.Lock()
			defer mu.Unlock()
			seeds++
			if failSeed && cmd == "/seed users" {
				return 9, "user exists", nil
			}
			return 0, "", nil
		}
		return health(container, cmd)
	}
	attempt := 0
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger fire" {
			attempt++
			if attempt == 1 {
				// The target aborts and boots slower than the template's
				// healthcheck timeout.
				mu.Lock()
				notListeningUntil = time.Now().Add(1500 * time.Millisecond)
				mu.Unlock()
				f.fe.Exit(f.target, 1)
				return 0, "", nil
			}
			f.report(attempt, asanResolverUAF)
		}
		return 0, "", nil
	})
	r := f.run(context.Background(), &contract.SequenceProbe{Attempts: 3,
		Steps: raceSteps(expectHit("heap-use-after-free", ""))})
	if !r.OK || outcomes(r) != "fail,hit" && outcomes(r) != "not_reached,hit" {
		t.Fatalf("outcomes %s: %+v", outcomes(r), r)
	}
	if !r.Attempts[1].Restarted {
		t.Errorf("attempt 2 not marked restarted: %+v", r.Attempts)
	}
	mu.Lock()
	if seeds != 2 {
		t.Errorf("%d seed steps ran after the restart, want 2", seeds)
	}
	failSeed, seeds, attempt = true, 0, 0
	mu.Unlock()
	if !f.h.Ready {
		t.Fatal("not ready")
	}
	r = f.run(context.Background(), &contract.SequenceProbe{Attempts: 3,
		Steps: raceSteps(expectHit("heap-use-after-free", ""))})
	if !r.OK || !strings.Contains(r.Detail, `seed step "/seed users" failed after the restart: exit 9`) {
		t.Fatalf("%+v", r)
	}
	if seeds != 1 {
		t.Errorf("%d seed steps ran after a failed one, want 1", seeds)
	}
}

// untrackStepPID returns the command trackStepPID wrapped, or ok false.
func untrackStepPID(wrapped string) (command, pidFile string, ok bool) {
	rest, found := strings.CutPrefix(wrapped, "sh -c '")
	if !found {
		return "", "", false
	}
	end := strings.LastIndex(rest, `' & p=$!; echo "$p" > '`)
	if end < 0 {
		return "", "", false
	}
	command = strings.ReplaceAll(rest[:end], `'\''`, "'")
	tail := rest[end+len(`' & p=$!; echo "$p" > '`):]
	pidFile, _, _ = strings.Cut(tail, "'")
	return command, pidFile, trackStepPID(command, pidFile) == wrapped
}

// tailEngine answers ContainerLogs as the API engine does: the last `tail`
// lines, of which only the first capBytes are kept.
type tailEngine struct {
	*enginetest.Fake
	mu       sync.Mutex
	lines    []string
	capBytes int
}

func (e *tailEngine) ContainerLogs(_ context.Context, _ string, tail int) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ls := e.lines
	if tail > 0 && tail < len(ls) {
		ls = ls[len(ls)-tail:]
	}
	s := strings.Join(ls, "")
	if len(s) > e.capBytes {
		s = s[:e.capBytes]
	}
	return s, nil
}

func (e *tailEngine) add(line string) {
	e.mu.Lock()
	e.lines = append(e.lines, line+"\n")
	e.mu.Unlock()
}

// #136 item 6: on a log whose last logTailLines lines exceed the engine's
// read cap, an old line is not taken as new and the new ones are seen.
func TestSequenceExpectLogLongLinesPastCap(t *testing.T) {
	f := newSeqFix(t)
	te := &tailEngine{Fake: f.fe, capBytes: 1 << 20}
	f.r.Engine = te
	for i := range 3000 {
		line := fmt.Sprintf("%05d %s", i, strings.Repeat("x", 900))
		if i == 2158 {
			line = fmt.Sprintf("%05d OLD-MARKER %s", i, strings.Repeat("x", 880))
		}
		te.add(line)
	}
	r := f.run(context.Background(), &contract.SequenceProbe{Steps: []contract.SequenceStep{
		execStep("", "/bin/true"), expectLog("OLD-MARKER"),
	}})
	if r.OK || outcomes(r) != "not_reached" {
		t.Fatalf("an old line counted as new: %+v", r)
	}
	f.setExec(func(_, cmd string) (int, string, error) {
		te.add("NEW-MARKER served")
		return 0, "", nil
	})
	r = f.run(context.Background(), &contract.SequenceProbe{Steps: []contract.SequenceStep{
		execStep("", "/bin/true"), expectLog("NEW-MARKER"),
	}})
	if !r.OK || outcomes(r) != "pass" {
		t.Fatalf("the new line was not seen: %+v", r)
	}
}

// #136 item 4: the wrapper keeps the command's output, exit code and quoting
// under a real sh, removes its PID file when the command ends, and the kill
// stops a command still running.
func TestTrackStepPIDShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	pidFile := filepath.Join(t.TempDir(), "step.pid")
	cmd := `printf '%s|' "it's" "a b"; echo err >&2; exit 3`
	w := trackStepPID(cmd, pidFile)
	if orig, pf, ok := untrackStepPID(w); !ok || orig != cmd || pf != pidFile {
		t.Fatalf("untrack: %q %q %v", orig, pf, ok)
	}
	out, err := exec.Command(sh, "-c", w).CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("exit: %v", err)
	}
	if string(out) != "it's|a b|err\n" {
		t.Errorf("output %q", out)
	}
	if _, err := os.Stat(pidFile); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("PID file left behind: %v", err)
	}

	// A command that would run on: killed through its PID file.
	start := time.Now()
	run := exec.Command(sh, "-c", trackStepPID("sleep 30", pidFile))
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	for time.Since(start) < 5*time.Second {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	f := shellQuote(pidFile)
	kill := fmt.Sprintf(`p=$(cat %s 2>/dev/null) && kill -9 "$p" 2>/dev/null; rm -f %s`, f, f)
	if out, err := exec.Command(sh, "-c", kill).CombinedOutput(); err != nil {
		t.Fatalf("kill: %v %s", err, out)
	}
	_ = run.Wait()
	if time.Since(start) > 10*time.Second {
		t.Fatal("the command was not killed")
	}
}

// A step cut off by its timeout is killed through its PID file, in the
// container it ran in; a step that succeeds is not.
func TestSequenceKillsStepLeftRunning(t *testing.T) {
	f := newSeqFix(t)
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger hang" {
			return -1, "", errors.New("exec timed out: context deadline exceeded")
		}
		return 0, "", nil
	})
	r := f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(execStep("driver", "/trigger hang"), expectNone())})
	if outcomes(r) != "not_reached" {
		t.Fatalf("%+v", r)
	}
	f.mu.Lock()
	kills := append([]string(nil), f.kills...)
	f.mu.Unlock()
	if len(kills) != 1 || !strings.HasPrefix(kills[0], f.driver+": ") {
		t.Fatalf("kills %q", kills)
	}
	var pidFile string
	for _, c := range f.fe.Calls {
		if prefix, cmd, ok := strings.Cut(c, ": "); ok && strings.HasSuffix(prefix, f.driver) {
			if orig, pf, ok := untrackStepPID(cmd); ok && orig == "/trigger hang" {
				pidFile = pf
			}
		}
	}
	if pidFile == "" || !strings.Contains(kills[0], shellQuote(pidFile)) {
		t.Errorf("kill %q does not use the step's PID file %q", kills[0], pidFile)
	}
}
