package runner

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

// Sequence executor limits. They are variables so tests can shorten them.
var (
	// MaxFreezeWindow bounds how long a sequence may keep the target frozen.
	// Past it the target is unpaused and the attempt is not reached.
	MaxFreezeWindow = 30 * time.Second
	// unpauseTimeout bounds the unpause that ends a freeze. It runs on a
	// fresh context, so a cancelled or timed-out attempt still thaws.
	unpauseTimeout = 15 * time.Second
	// assertWindow is how long expect_sanitizer and expect_log wait for the
	// report or log line to appear (a report is written, and symbolized, after
	// resume). expect_sanitizer: none watches for the whole window.
	assertWindow = 5 * time.Second
	// assertPoll is how often those steps look again within the window.
	assertPoll = 100 * time.Millisecond
	// exitSettle is how long, between attempts, a running target is watched
	// for an exit: a sanitizer report is complete a moment before the
	// process aborts (halt_on_error=1), so the target may still be going
	// down when the attempt that hit ends.
	exitSettle = time.Second
	// exitPoll is how often the target is inspected within exitSettle.
	exitPoll = 50 * time.Millisecond
)

const (
	// maxReportBytes caps how much of each sanitizer log file is read.
	maxReportBytes = 1 << 20
	// logExactLimit is the log size up to which a whole-log read is complete
	// in every engine (they cap a read at 1 MiB or more), so the log written
	// during an attempt is an exact slice. Past it the runner compares tails.
	logExactLimit = 768 << 10
	// logTailLines is how many trailing log lines a tail comparison reads.
	logTailLines = 2000
)

// errNoPause is the verify detail of a sequence with freeze on an engine that
// cannot pause containers.
const errNoPause = "this engine cannot pause containers, so freeze cannot run"

// sequenceExec runs sequence probes for one target state through the engine.
type sequenceExec struct {
	r    *Runner
	c    *contract.Contract
	h    *Handle
	exec probes.ExecFunc
	// net returns the target for network steps, or why there is none from
	// here (the same reasons runProbes skips network probes for).
	net func() (probes.Target, string)
}

// sequenceFunc is the probes.SequenceFunc of a target state.
func (r *Runner) sequenceFunc(c *contract.Contract, h *Handle, exec probes.ExecFunc) probes.SequenceFunc {
	x := &sequenceExec{r: r, c: c, h: h, exec: exec, net: func() (probes.Target, string) { return r.networkTarget(c, h, exec) }}
	return x.run
}

// seqStats tallies attempt outcomes.
type seqStats struct{ hit, pass, fail, notReached int }

// run runs up to s.Attempts attempts and decides the probe:
//   - with a positive expect_sanitizer it passes once MinHits attempts hit,
//     and fails as soon as that can no longer happen;
//   - without one it fails on the first failed attempt and passes on the
//     first passing one (attempts only absorb harness errors);
//   - when no attempt reached the race, it fails with the last reason.
func (x *sequenceExec) run(ctx context.Context, s *contract.SequenceProbe) probes.Result {
	if why := x.preflight(ctx, s); why != "" {
		return probes.Result{Detail: "sequence: " + why}
	}
	positive := hasPositiveSanitizer(s)
	n, minHits := s.AttemptCount(), s.MinHitCount()
	var attempts []probes.SequenceAttempt
	var st seqStats
	decided := func(i int) bool {
		if positive {
			return st.hit >= minHits || st.hit+(n-i) < minHits
		}
		return st.fail > 0 || st.pass > 0
	}
	for i := 1; i <= n; i++ {
		if ctx.Err() != nil {
			break
		}
		restarted := false
		if i > 1 {
			var err error
			if restarted, err = x.ensureRunning(ctx); err != nil {
				// No later attempt can run either.
				for j := i; j <= n; j++ {
					attempts = append(attempts, probes.SequenceAttempt{Attempt: j, Outcome: probes.OutcomeNotReached, Detail: err.Error()})
					st.notReached++
				}
				break
			}
		}
		a := x.attempt(ctx, s, i)
		a.Restarted = restarted
		attempts = append(attempts, a)
		switch a.Outcome {
		case probes.OutcomeHit:
			st.hit++
		case probes.OutcomePass:
			st.pass++
		case probes.OutcomeFail:
			st.fail++
		default:
			st.notReached++
		}
		if decided(i) {
			break
		}
	}
	ok := st.fail == 0 && st.pass > 0
	if positive {
		ok = st.hit >= minHits
	}
	return probes.Result{OK: ok, Detail: sequenceDetail(positive, minHits, st, attempts, ctx.Err() != nil), Attempts: attempts}
}

// sequenceDetail renders the probe's one-line detail: the tally, then every
// attempt's outcome and reason.
func sequenceDetail(positive bool, minHits int, st seqStats, attempts []probes.SequenceAttempt, cancelled bool) string {
	ran := len(attempts)
	var head string
	switch {
	case ran == 0 && cancelled:
		return "sequence: cancelled before the first attempt"
	case ran > 0 && st.notReached == ran:
		head = fmt.Sprintf("sequence: no attempt reached the race (%d/%d not reached), last: %s", ran, ran, attempts[ran-1].Detail)
	case positive:
		head = fmt.Sprintf("sequence: %d/%d hits (min %d)", st.hit, ran, minHits)
	default:
		head = fmt.Sprintf("sequence: %d/%d passed, %d failed", st.pass, ran, st.fail)
	}
	if cancelled {
		head += ", cancelled"
	}
	parts := make([]string, 0, len(attempts))
	for _, a := range attempts {
		p := fmt.Sprintf("#%d %s: %s", a.Attempt, strings.ReplaceAll(a.Outcome, "_", " "), a.Detail)
		if a.Restarted {
			p = fmt.Sprintf("#%d (target restarted) %s: %s", a.Attempt, strings.ReplaceAll(a.Outcome, "_", " "), a.Detail)
		}
		parts = append(parts, p)
	}
	return head + ": " + strings.Join(parts, "; ")
}

func hasPositiveSanitizer(s *contract.SequenceProbe) bool {
	for _, st := range s.Steps {
		if st.ExpectSanitizer != nil && st.ExpectSanitizer.Positive() {
			return true
		}
	}
	return false
}

func hasStep(s *contract.SequenceProbe, kind string) bool {
	for _, st := range s.Steps {
		if st.Kind() == kind {
			return true
		}
	}
	return false
}

// logDir is the target's sanitizer log directory, or "".
func (x *sequenceExec) logDir() string {
	if x.c.Service.Sanitizer == nil {
		return ""
	}
	return x.c.Service.Sanitizer.LogDir
}

// preflight checks what every attempt needs before the first one runs: the
// engine's optional capabilities and the sanitizer log directory's mode. It
// returns why the sequence cannot run, or "".
func (x *sequenceExec) preflight(ctx context.Context, s *contract.SequenceProbe) string {
	if hasStep(s, "freeze") || hasStep(s, "resume") {
		if _, ok := x.r.Engine.(engine.Pauser); !ok {
			return errNoPause
		}
	}
	dir := x.logDir()
	if dir == "" {
		if hasStep(s, "expect_sanitizer") {
			return "expect_sanitizer needs service.sanitizer.log_dir"
		}
		return ""
	}
	fr, ok := x.r.Engine.(engine.FileReader)
	if !ok {
		return fmt.Sprintf("sanitizer log_dir %s: this engine cannot read files from containers", dir)
	}
	mode, err := fr.ContainerStatPath(ctx, x.h.Container, dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Sprintf("sanitizer log_dir %s does not exist", dir)
	case err != nil:
		return fmt.Sprintf("sanitizer log_dir %s: %v", dir, err)
	case !mode.IsDir():
		return fmt.Sprintf("sanitizer log_dir %s is not a directory (mode %s)", dir, mode)
	case mode.Perm() != 0o777:
		// A report the sanitizer cannot write is lost without a trace
		// (EACCES): make that an error instead.
		return fmt.Sprintf("sanitizer log_dir %s is not writable by every user (mode %s)", dir, octalMode(mode))
	}
	return ""
}

// octalMode renders permission bits and the sticky bit as 0755 / 1777.
func octalMode(m fs.FileMode) string {
	v := uint32(m.Perm())
	if m&fs.ModeSticky != 0 {
		v |= 0o1000
	}
	if m&fs.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&fs.ModeSetuid != 0 {
		v |= 0o4000
	}
	return fmt.Sprintf("%04o", v)
}

// ensureRunning starts the target again when it exited during the previous
// attempt (e.g. a server built with halt_on_error=1) and waits for it to be
// ready, as Run does. A target still running is watched for exitSettle
// first, in case it is on its way down. It reports whether it restarted the
// target.
func (x *sequenceExec) ensureRunning(ctx context.Context) (bool, error) {
	var det *engine.ContainerDetail
	deadline := time.Now().Add(exitSettle)
	for {
		var err error
		if det, err = x.r.Engine.ContainerInspect(ctx, x.h.Container); err != nil {
			return false, fmt.Errorf("the target is gone: %v", err)
		}
		if !det.Running || !time.Now().Before(deadline) || ctx.Err() != nil {
			break
		}
		sleepCtx(ctx, min(exitPoll, time.Until(deadline)))
	}
	if det.Running {
		return false, nil
	}
	code := det.ExitCode
	if err := x.r.Engine.ContainerStart(ctx, x.h.Container); err != nil {
		return false, fmt.Errorf("the target exited with code %d and could not be started again: %v", code, err)
	}
	x.r.refreshAddress(ctx, x.h)
	x.r.awaitReady(ctx, x.c, x.h, 0)
	if !x.h.Ready {
		return true, fmt.Errorf("the target exited with code %d and was not ready after a restart: %s", code, x.h.ReadyDetail)
	}
	return true, nil
}

// refreshAddress re-reads the target's address after a restart: the daemon
// may assign another IP, or other host ports to ports published on host
// port 0.
func (r *Runner) refreshAddress(ctx context.Context, h *Handle) {
	det, err := r.Engine.ContainerInspect(ctx, h.Container)
	if err != nil {
		return
	}
	switch h.Exposure.Mode {
	case ModeHost:
		_ = assignedHostPorts(h, det)
		if len(h.PublishedPorts) > 0 {
			h.EndpointPort = h.PublishedPorts[0].HostPort
		}
	case ModeInternal, ModeMacvlan:
		if h.IP == "" {
			return // not reachable from here before either
		}
		prefer := h.Exposure.Network
		if h.Exposure.Mode == ModeMacvlan {
			prefer = "vulnsuite-macvlan-" + h.Exposure.Parent
		}
		if ip := pickIP(det.IPs, prefer, h.SidecarNetwork); ip != "" {
			if h.Exposure.Mode == ModeMacvlan && h.Exposure.IP == "" {
				h.EndpointHost = ip
			}
			h.IP = ip
		}
	}
}

// -- one attempt ----------------------------------------------------------------

// freezer pauses and unpauses the target and guarantees it never stays
// frozen: Thaw is idempotent and runs on a fresh context, and a timer thaws
// the target (and cancels the attempt) once MaxFreezeWindow passes.
type freezer struct {
	mu        sync.Mutex
	p         engine.Pauser
	container string
	frozen    bool
	capped    bool
	timer     *time.Timer
	parent    context.Context
	onCap     func()
	thawErr   error
}

func (f *freezer) freeze(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.frozen {
		return errors.New("the target is already frozen")
	}
	if err := f.p.ContainerPause(ctx, f.container); err != nil {
		return err
	}
	f.frozen = true
	f.timer = time.AfterFunc(MaxFreezeWindow, f.capWindow)
	return nil
}

// capWindow ends a freeze that outlived MaxFreezeWindow.
func (f *freezer) capWindow() {
	f.mu.Lock()
	capped := f.frozen
	if capped {
		f.capped = true
		_ = f.thawLocked()
	}
	f.mu.Unlock()
	if capped {
		f.onCap() // stop the step that outlived the window
	}
}

// thaw unpauses the target when it is frozen. It returns the error of the
// unpause that ended the last freeze, if that failed.
func (f *freezer) thaw() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.thawLocked()
}

func (f *freezer) thawLocked() error {
	if !f.frozen {
		return f.thawErr
	}
	if f.timer != nil {
		f.timer.Stop()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(f.parent), unpauseTimeout)
	defer cancel()
	err := f.p.ContainerUnpause(ctx, f.container)
	f.frozen = false
	if err != nil {
		f.thawErr = fmt.Errorf("unpause the target: %w", err)
	}
	return f.thawErr
}

func (f *freezer) wasCapped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.capped
}

// attemptState collects what one attempt's steps found.
type attemptState struct {
	notReached string   // the first reason the race was not shown to run
	noneFail   string   // an expect_sanitizer: none that saw a report
	posFail    string   // a positive expect_sanitizer that did not hold
	hit        string   // the first positive expect_sanitizer that held
	held       []string // what the held assertions showed, for a pass
	logMark    *logMark
	snapshot   map[string]logFile
}

// attempt runs the steps once under the attempt timeout and classifies the
// outcome. The target is never left frozen: every exit path thaws it.
func (x *sequenceExec) attempt(parent context.Context, s *contract.SequenceProbe, n int) (a probes.SequenceAttempt) {
	start := time.Now()
	a.Attempt = n
	ctx, cancel := context.WithTimeout(parent, s.TimeoutDuration())
	defer cancel()
	var fz *freezer
	if p, ok := x.r.Engine.(engine.Pauser); ok {
		fz = &freezer{p: p, container: x.h.Container, parent: parent, onCap: cancel}
	}
	var as attemptState
	defer func() {
		// Thaw on every path: a step error, the attempt timeout, Ctrl-C, or a
		// sequence that never reached its resume.
		if fz != nil {
			if err := fz.thaw(); err != nil && a.Outcome != probes.OutcomeFail {
				a.Outcome, a.Detail = probes.OutcomeNotReached, err.Error()
			} else if err != nil {
				a.Detail += "; " + err.Error()
			}
		}
		a.Elapsed = time.Since(start)
	}()

	stepFailed := func(i int, st contract.SequenceStep, err error) string {
		switch {
		case fz != nil && fz.wasCapped():
			return fmt.Sprintf("the target stayed frozen longer than %s (step %d, %s); it was unpaused", MaxFreezeWindow, i+1, st.Kind())
		case parent.Err() != nil:
			return fmt.Sprintf("cancelled at step %d (%s)", i+1, st.Kind())
		case ctx.Err() != nil:
			return fmt.Sprintf("timed out after %s at step %d (%s)", s.TimeoutDuration(), i+1, st.Kind())
		}
		return err.Error()
	}

	if hasStep(s, "expect_log") {
		m, err := x.markLogs(ctx)
		if err != nil {
			as.notReached = "read the target's logs: " + err.Error()
		}
		as.logMark = m
	}
	if dir := x.logDir(); dir != "" && as.notReached == "" {
		snap, err := x.snapshotLogDir(ctx, dir)
		if err != nil {
			as.notReached = fmt.Sprintf("list sanitizer log_dir %s: %v", dir, err)
		}
		as.snapshot = snap
	}

steps:
	for i, st := range s.Steps {
		if as.notReached != "" {
			break
		}
		if ctx.Err() != nil {
			as.notReached = stepFailed(i, st, ctx.Err())
			break
		}
		switch {
		case st.Exec != nil:
			container := x.h.Container
			if !st.Exec.InTarget() {
				container = SidecarContainerName(x.c.ID(), x.h.State, st.Exec.Container)
			}
			e := st.Exec.ExecProbe
			r := probes.Run(ctx, contract.Probe{Exec: &e}, probes.Target{Container: container, Exec: x.exec})
			if !r.OK {
				as.notReached = stepFailed(i, st, errors.New(sidecarDetail(st.Exec, r.Detail)))
				break steps
			}
			if st.Exec.Asserts() {
				as.held = append(as.held, sidecarDetail(st.Exec, r.Detail))
			}
		case st.Freeze != nil:
			if fz == nil {
				as.notReached = errNoPause
				break steps
			}
			if err := fz.freeze(ctx); err != nil {
				as.notReached = stepFailed(i, st, fmt.Errorf("freeze: %v", err))
				break steps
			}
		case st.Resume != nil:
			if fz == nil {
				as.notReached = errNoPause
				break steps
			}
			capped := fz.wasCapped()
			if err := fz.thaw(); err != nil || capped {
				as.notReached = stepFailed(i, st, fmt.Errorf("resume: %v", err))
				break steps
			}
		case st.Sleep != nil:
			sleepCtx(ctx, time.Duration(st.Sleep.MS)*time.Millisecond)
			if ctx.Err() != nil {
				as.notReached = stepFailed(i, st, ctx.Err())
				break steps
			}
		case st.HTTP != nil, st.TCP != nil, st.Net != nil:
			tgt, why := x.net()
			if why != "" {
				as.notReached = fmt.Sprintf("%s step %d cannot run: %s", st.Kind(), i+1, why)
				break steps
			}
			r := probes.Run(ctx, contract.Probe{HTTP: st.HTTP, TCP: st.TCP, Net: st.Net}, tgt)
			if !r.OK {
				as.notReached = stepFailed(i, st, errors.New(r.Detail))
				break steps
			}
		case st.ExpectLog != nil:
			if why := x.expectLog(ctx, as.logMark, *st.ExpectLog); why != "" {
				if ctx.Err() != nil {
					why = stepFailed(i, st, ctx.Err())
				}
				as.notReached = why
				break steps
			}
			as.held = append(as.held, fmt.Sprintf("log ~ /%s/", *st.ExpectLog))
		case st.ExpectSanitizer != nil:
			held, why, err := x.expectSanitizer(ctx, as.snapshot, *st.ExpectSanitizer)
			switch {
			case err != nil:
				as.notReached = stepFailed(i, st, err)
				break steps
			case !held && st.ExpectSanitizer.None:
				as.noneFail = why
			case !held:
				if as.posFail == "" {
					as.posFail = why
				}
			case st.ExpectSanitizer.None:
				as.held = append(as.held, why)
			case as.hit == "":
				as.hit = why
			}
		}
		if fz != nil && fz.wasCapped() && as.notReached == "" {
			// The step outlived the freeze window (and ignored the
			// cancellation): its result does not count.
			as.notReached = stepFailed(i, st, nil)
			break
		}
	}

	// A report on patched is decisive whatever else happened; otherwise a
	// race that was not shown to run decides nothing.
	switch {
	case as.noneFail != "":
		a.Outcome, a.Detail = probes.OutcomeFail, as.noneFail
	case as.notReached != "":
		a.Outcome, a.Detail = probes.OutcomeNotReached, as.notReached
	case as.posFail != "":
		a.Outcome, a.Detail = probes.OutcomeFail, as.posFail
	case as.hit != "":
		a.Outcome, a.Detail = probes.OutcomeHit, as.hit
	default:
		a.Outcome, a.Detail = probes.OutcomePass, strings.Join(as.held, "; ")
		if a.Detail == "" {
			a.Detail = "every step held"
		}
	}
	return a
}

// sidecarDetail names the sidecar an exec step ran in.
func sidecarDetail(e *contract.SequenceExec, detail string) string {
	if e.InTarget() {
		return detail
	}
	return e.Container + ": " + detail
}

// -- sanitizer oracle -------------------------------------------------------------

// logFile is what a snapshot remembers of one file in the log directory.
type logFile struct {
	size    int64
	modTime time.Time
	read    int64    // bytes of it read (the cap may cut it)
	sum     [32]byte // sha256 of the bytes read
}

// snapshotLogDir records every file in the log directory: its size,
// modification time and a hash of its content. A restarted single-process
// target gets the same PID, so ASan rewrites the same asan.<pid> file, often
// to the same size; the time and the hash tell such a rewrite apart.
func (x *sequenceExec) snapshotLogDir(ctx context.Context, dir string) (map[string]logFile, error) {
	files, err := x.r.Engine.(engine.FileReader).ContainerReadDir(ctx, x.h.Container, dir, maxReportBytes)
	if err != nil {
		return nil, err
	}
	snap := make(map[string]logFile, len(files))
	for name, f := range files {
		snap[name] = logFile{size: f.Size, modTime: f.ModTime, read: int64(len(f.Data)), sum: sha256.Sum256(f.Data)}
	}
	return snap, nil
}

// newReports parses the reports written to the log directory since snap:
// new files, what was appended to existing ones, and the whole of a file
// that was rewritten.
func (x *sequenceExec) newReports(ctx context.Context, snap map[string]logFile) ([]SanitizerReport, error) {
	files, err := x.r.Engine.(engine.FileReader).ContainerReadDir(ctx, x.h.Container, x.logDir(), maxReportBytes)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []SanitizerReport
	for _, name := range names {
		f := files[name]
		data := f.Data
		if old, ok := snap[name]; ok {
			if f.Size == old.size && f.ModTime.Equal(old.modTime) && sha256.Sum256(data) == old.sum {
				continue // unchanged
			}
			if f.Size > old.size && old.read == old.size && int64(len(data)) >= old.size && sha256.Sum256(data[:old.size]) == old.sum {
				data = data[old.size:] // appended to
			}
		}
		out = append(out, ParseSanitizerReports(string(data))...)
	}
	return out, nil
}

// expectSanitizer runs an expect_sanitizer step. A positive one holds as soon
// as a new report of its kind has a first-stack frame matching its frame
// regexp, and fails when none has by the end of assertWindow. `none` holds
// when no new report appears during the whole window, and fails on the first.
// why describes the outcome; err is a failure to read the directory, or the
// attempt's context ending before the step decided.
func (x *sequenceExec) expectSanitizer(ctx context.Context, snap map[string]logFile, e contract.ExpectSanitizer) (held bool, why string, err error) {
	deadline := time.Now().Add(assertWindow)
	var seen []SanitizerReport
	for {
		reports, err := x.newReports(ctx, snap)
		if err != nil && ctx.Err() == nil {
			return false, "", fmt.Errorf("read sanitizer log_dir %s: %v", x.logDir(), err)
		}
		if err == nil {
			seen = reports
		}
		if e.None && len(seen) > 0 {
			return false, "sanitizer report: " + seen[0].Summary(), nil
		}
		if !e.None {
			for _, r := range seen {
				if !r.MatchesKind(e.Kind) {
					continue
				}
				if f, ok := r.MatchFrame(e.Frame); ok {
					if f.String() == "" {
						return true, r.Kind, nil
					}
					return true, r.Kind + " at " + f.String(), nil
				}
			}
		}
		if ctx.Err() != nil {
			// The window was cut short (timeout, Ctrl-C, freeze cap):
			// nothing was decided.
			return false, "", ctx.Err()
		}
		if !time.Now().Before(deadline) {
			break
		}
		sleepCtx(ctx, min(assertPoll, time.Until(deadline)))
	}
	if e.None {
		return true, "no sanitizer report", nil
	}
	want := e.Kind
	if e.Frame != "" {
		want += fmt.Sprintf(" report with a frame ~ /%s/", e.Frame)
	} else {
		want += " report"
	}
	if len(seen) == 0 {
		return false, fmt.Sprintf("no sanitizer report (want %s)", want), nil
	}
	got := make([]string, 0, len(seen))
	for _, r := range seen {
		got = append(got, r.Summary())
	}
	return false, fmt.Sprintf("no %s; reports: %s", want, strings.Join(got, ", ")), nil
}

// -- log oracle -------------------------------------------------------------------

// logMark is where the target's log stood when an attempt started.
type logMark struct {
	// offset is the log's length, valid when exact is set.
	offset int
	exact  bool
	// tail is the log's last lines then, for a log too long to read whole.
	tail []string
}

// markLogs records the log's length (or, for a long log, its tail).
func (x *sequenceExec) markLogs(ctx context.Context) (*logMark, error) {
	full, err := x.r.Engine.ContainerLogs(ctx, x.h.Container, 0)
	if err != nil {
		return nil, err
	}
	if len(full) < logExactLimit {
		return &logMark{offset: len(full), exact: true, tail: lastLines(full, logTailLines)}, nil
	}
	t, err := x.r.Engine.ContainerLogs(ctx, x.h.Container, logTailLines)
	if err != nil {
		return nil, err
	}
	return &logMark{tail: lastLines(t, logTailLines)}, nil
}

// logsSince returns what the target logged after m.
func (x *sequenceExec) logsSince(ctx context.Context, m *logMark) (string, error) {
	if m.exact {
		full, err := x.r.Engine.ContainerLogs(ctx, x.h.Container, 0)
		if err != nil {
			return "", err
		}
		if len(full) < logExactLimit && len(full) >= m.offset {
			return full[m.offset:], nil
		}
	}
	t, err := x.r.Engine.ContainerLogs(ctx, x.h.Container, logTailLines)
	if err != nil {
		return "", err
	}
	return linesAfter(m.tail, t), nil
}

// expectLog waits up to assertWindow for pat to match the log written since
// m. It returns "" when it matched, else why not.
func (x *sequenceExec) expectLog(ctx context.Context, m *logMark, pat string) string {
	deadline := time.Now().Add(assertWindow)
	got := ""
	for {
		since, err := x.logsSince(ctx, m)
		if err != nil && ctx.Err() == nil {
			return "read the target's logs: " + err.Error()
		}
		if err == nil {
			got = since
			if probes.MatchDotAll(pat, got) {
				return ""
			}
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			break
		}
		sleepCtx(ctx, min(assertPoll, time.Until(deadline)))
	}
	return fmt.Sprintf("the log written during the attempt (%d bytes) !~ /%s/", len(got), pat)
}

// lastLines splits s into lines (each keeping its newline) and returns the
// last n.
func lastLines(s string, n int) []string {
	ls := strings.SplitAfter(s, "\n")
	if len(ls) > 0 && ls[len(ls)-1] == "" {
		ls = ls[:len(ls)-1]
	}
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return ls
}

// linesAfter returns the part of now (a log tail read later) that follows
// prev (the tail read before): the lines after the longest suffix of prev
// that now starts with. prev's last line may have been incomplete then, so it
// matches as a prefix. Without any overlap all of now is new.
func linesAfter(prev []string, now string) string {
	cur := lastLines(now, len(strings.SplitAfter(now, "\n")))
	for s := 0; s < len(prev); s++ {
		k := len(prev) - s
		if k > len(cur) {
			continue
		}
		match := true
		for j := 0; j < k; j++ {
			p, c := prev[s+j], cur[j]
			if j == k-1 {
				if !strings.HasPrefix(c, p) {
					match = false
				}
			} else if p != c {
				match = false
			}
			if !match {
				break
			}
		}
		if match {
			rest := strings.TrimPrefix(cur[k-1], prev[len(prev)-1])
			return rest + strings.Join(cur[k:], "")
		}
	}
	return now
}
