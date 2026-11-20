package runner

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// flakyPauser wraps the fake to make pause and unpause misbehave as a daemon
// can: a pause that lands although its request fails here, and unpauses
// that fail a few times before they work.
type flakyPauser struct {
	*enginetest.Fake
	mu sync.Mutex
	// pauseLandsThenFails: the next pause pauses the container, then
	// returns an error, as a request cut off by a deadline can.
	pauseLandsThenFails bool
	// unpauseFailures fails that many unpauses before letting one through.
	unpauseFailures int
}

func (p *flakyPauser) ContainerPause(ctx context.Context, id string) error {
	p.mu.Lock()
	fail := p.pauseLandsThenFails
	p.pauseLandsThenFails = false
	p.mu.Unlock()
	if err := p.Fake.ContainerPause(ctx, id); err != nil {
		return err
	}
	if fail {
		return context.DeadlineExceeded
	}
	return nil
}

func (p *flakyPauser) ContainerUnpause(ctx context.Context, id string) error {
	p.mu.Lock()
	fail := p.unpauseFailures > 0
	if fail {
		p.unpauseFailures--
	}
	p.mu.Unlock()
	if fail {
		return errors.New("daemon busy")
	}
	return p.Fake.ContainerUnpause(ctx, id)
}

func shortUnpauseRetry(t *testing.T) {
	t.Helper()
	old := unpauseRetry
	unpauseRetry = 5 * time.Millisecond
	t.Cleanup(func() { unpauseRetry = old })
}

func hitOnFire(f *seqFix) {
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger fire" {
			f.report(1, asanResolverUAF)
		}
		return 0, "", nil
	})
}

// #131 item 1: a pause whose request fails after the daemon paused the
// target must not leave it paused for every later attempt.
func TestSequencePauseThatLandsIsUndone(t *testing.T) {
	f := newSeqFix(t)
	shortUnpauseRetry(t)
	fp := &flakyPauser{Fake: f.fe, pauseLandsThenFails: true}
	f.r.Engine = fp
	hitOnFire(f)
	r := f.run(context.Background(), &contract.SequenceProbe{Attempts: 2,
		Steps: raceSteps(expectHit("heap-use-after-free", "ngx_resolver_process_a"))})
	if !r.OK || outcomes(r) != "not_reached,hit" {
		t.Fatalf("want the second attempt to run on an unpaused target: %+v", r)
	}
	if f.paused() {
		t.Fatal("the target was left paused")
	}
}

// #131 item 2: an unpause that fails is retried, so a transient daemon error
// does not leave the target paused.
func TestSequenceUnpauseIsRetried(t *testing.T) {
	f := newSeqFix(t)
	shortUnpauseRetry(t)
	f.r.Engine = &flakyPauser{Fake: f.fe, unpauseFailures: 2}
	hitOnFire(f)
	r := f.run(context.Background(), &contract.SequenceProbe{
		Steps: raceSteps(expectHit("heap-use-after-free", "ngx_resolver_process_a"))})
	if !r.OK || outcomes(r) != "hit" {
		t.Fatalf("%+v", r)
	}
	if f.paused() {
		t.Fatal("the target was left paused")
	}
}

// An unpause that keeps failing in one attempt is retried before the next.
func TestSequenceLeftPausedIsUnpausedBeforeNextAttempt(t *testing.T) {
	f := newSeqFix(t)
	shortUnpauseRetry(t)
	old := unpauseTimeout
	unpauseTimeout = 30 * time.Millisecond
	t.Cleanup(func() { unpauseTimeout = old })
	fp := &flakyPauser{Fake: f.fe, unpauseFailures: 1 << 30}
	f.r.Engine = fp
	hitOnFire(f)
	go func() {
		// The daemon recovers while attempt 1 is being given up on.
		time.Sleep(60 * time.Millisecond)
		fp.mu.Lock()
		fp.unpauseFailures = 0
		fp.mu.Unlock()
	}()
	r := f.run(context.Background(), &contract.SequenceProbe{Attempts: 3,
		Steps: raceSteps(sleepMS(80), expectHit("heap-use-after-free", "ngx_resolver_process_a"))})
	if !r.OK || !strings.HasSuffix(outcomes(r), "hit") {
		t.Fatalf("%+v", r)
	}
	if f.paused() {
		t.Fatal("the target was left paused")
	}
}

// #131 item 3: the attempt that decides the probe may kill the target
// (halt_on_error=1); it is started again so later probes and the scanner
// find it up.
func TestSequenceRestartsTargetAfterDecidingAttempt(t *testing.T) {
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
	r := f.run(context.Background(), &contract.SequenceProbe{
		Steps: raceSteps(execStep("driver", "/trigger crash"), expectHit("heap-use-after-free", "ngx_resolver_process_a"))})
	if !r.OK || outcomes(r) != "hit" || !strings.Contains(r.Detail, "the target was restarted afterwards") {
		t.Fatalf("%+v", r)
	}
	if c := f.fe.Containers[f.target]; c == nil || !c.Running {
		t.Fatal("the target was left exited")
	}
	if !f.h.Ready {
		t.Fatal("the handle is not ready after the restart")
	}
	// A second sequence (as a second verify probe would) runs normally.
	r = f.run(context.Background(), &contract.SequenceProbe{
		Steps: raceSteps(execStep("driver", "/trigger crash"), expectHit("heap-use-after-free", "ngx_resolver_process_a"))})
	if outcomes(r) != "hit" {
		t.Fatalf("second sequence: %+v", r)
	}
}

// A target that cannot come back after the deciding attempt fails the run
// as not ready, and the probe says why.
func TestSequenceRestartAfterwardsFails(t *testing.T) {
	f := newSeqFix(t)
	f.fe.StartFn = func(engine.ContainerSpec) error { return errors.New("port is already allocated") }
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger crash" {
			// The thawed process hits the bug and aborts (halt_on_error=1).
			f.report(1, asanResolverUAF)
			f.fe.Exit(f.target, 1)
		}
		return 0, "", nil
	})
	r := f.run(context.Background(), &contract.SequenceProbe{
		Steps: raceSteps(execStep("driver", "/trigger crash"), expectHit("heap-use-after-free", "ngx_resolver_process_a"))})
	if !r.OK || !strings.Contains(r.Detail, "afterwards the target exited with code 1 and could not be started again") {
		t.Fatalf("%+v", r)
	}
}

// #131 item 4: a report file already past the read cap when the attempt
// started is not parsed again as new when it grows.
func TestSequenceTruncatedReportIsNotReread(t *testing.T) {
	f := newSeqFix(t)
	big := asanResolverUAF + strings.Repeat("x", maxReportBytes)
	f.report(1, big)
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger fire" {
			f.report(1, big+"more output past the cap\n")
		}
		return 0, "", nil
	})
	r := f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectNone())})
	if !r.OK || outcomes(r) != "pass" {
		t.Fatalf("the old report must not count as new: %+v", r)
	}
}

// #131 item 6: a sequence with a network step cannot run from a host that
// cannot reach the target; verify is skipped, not failed.
func TestRunNetworkSequenceUnreachableIsSkipped(t *testing.T) {
	shortWindows(t)
	seq := contract.Probe{Sequence: &contract.SequenceProbe{Steps: []contract.SequenceStep{
		{TCP: &contract.TCPProbe{Port: 8080}}, execStep("driver", "go"), expectNone(),
	}}}
	plain := contract.Probe{Sequence: &contract.SequenceProbe{Steps: []contract.SequenceStep{execStep("driver", "go"), expectNone()}}}
	for name, tc := range map[string]struct {
		verify []contract.Probe
		ok     any
		detail string
	}{
		"network sequence only": {[]contract.Probe{seq}, nil, "could not verify from this host"},
		"with a plain sequence": {[]contract.Probe{plain, seq}, nil, "skip 1 network probe(s)"},
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
			h, err := unreachableRunner(fe).Run(context.Background(), sequenceContract(tc.verify...), "vulnerable", DefaultExposure(),
				Options{Verify: true, Build: builder.Options{Pull: true}})
			if err != nil {
				t.Fatal(err)
			}
			if deref(h.VerifyOK) != tc.ok || !strings.Contains(h.VerifyDetail, tc.detail) {
				t.Fatalf("VerifyOK = %v, want %v; detail %q", deref(h.VerifyOK), tc.ok, h.VerifyDetail)
			}
		})
	}
}
