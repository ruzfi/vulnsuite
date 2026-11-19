package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/loader"
	"github.com/ruzfi/vulnsuite/pkg/runner"
	"github.com/ruzfi/vulnsuite/pkg/scanners"
)

// DefaultMaxConcurrent caps simultaneously running targets.
const DefaultMaxConcurrent = 10

// portMapFlag collects repeatable "container=host" pairs into a map, lazily
// allocating it on first use.
type portMapFlag struct{ m *map[int]int }

func (p portMapFlag) String() string { return "" }

func (p portMapFlag) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	cp, err1 := strconv.Atoi(strings.TrimSpace(k))
	hp, err2 := strconv.Atoi(strings.TrimSpace(val))
	if !ok || err1 != nil || err2 != nil || cp < 1 || cp > 65535 || hp < 1 || hp > 65535 {
		return fmt.Errorf("want container=host with ports 1..65535, got %q", v)
	}
	if *p.m == nil {
		*p.m = map[int]int{}
	}
	if _, dup := (*p.m)[cp]; dup {
		return fmt.Errorf("container port %d is mapped more than once", cp)
	}
	(*p.m)[cp] = hp
	return nil
}

// checkHostPortMap rejects -host-port-map keys that are not ports the target
// publishes in host mode: such a pin would be silently ignored.
func checkHostPortMap(m map[int]int, c *contract.Contract) error {
	pubs := c.Service.HostPublishPorts()
	published := map[int]bool{}
	var list []string
	for _, p := range pubs {
		published[p.Container] = true
		list = append(list, strconv.Itoa(p.Container))
	}
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		if !published[k] {
			return usageError{fmt.Sprintf("-host-port-map %d=%d: %s does not publish container port %d (it publishes %s)", k, m[k], c.ID(), k, strings.Join(list, ", "))}
		}
	}
	return nil
}

func addExposureFlags(fs *flag.FlagSet, exp *runner.Exposure) {
	fs.StringVar(&exp.Mode, "expose", runner.ModeInternal, "exposure mode: internal, host or macvlan")
	fs.StringVar(&exp.Network, "network", runner.DefaultNetwork, "internal network name")
	fs.BoolVar(&exp.Internal, "no-egress", false, "create the internal network with no route off the host")
	fs.StringVar(&exp.Bind, "bind", "127.0.0.1", "host bind address (host mode)")
	fs.IntVar(&exp.HostPort, "host-port", 0, "host port for the primary port (host mode, single target; default: a free port)")
	fs.Var(portMapFlag{&exp.HostPortMap}, "host-port-map", "pin an additional published port: container=host (host mode, single target; repeatable)")
	fs.StringVar(&exp.Parent, "parent", "", "host interface (macvlan mode)")
	fs.StringVar(&exp.IP, "ip", "", "static IP (macvlan mode, single target)")
	fs.StringVar(&exp.Subnet, "subnet", "", "subnet (macvlan mode)")
	fs.StringVar(&exp.Gateway, "gateway", "", "gateway (macvlan mode)")
}

func reportVerify(g *Global, h *runner.Handle, indent string) {
	switch {
	case h.VerifyOK != nil && *h.VerifyOK:
		g.printf("%sverify: ok -- confirmed %s\n", indent, h.State)
	case h.VerifyOK != nil:
		g.printf("%sverify: FAILED -- target may not be in the %s state:\n", indent, h.State)
		for _, line := range strings.Split(h.VerifyDetail, "\n") {
			g.printf("%s    %s\n", indent, line)
		}
	default:
		g.printf("%sverify: skipped (%s)\n", indent, h.VerifyDetail)
	}
}

// Reasons a target lands in a -summary's skipped or failed list. They are
// stable strings a pipeline can switch on; detail carries the human text.
const (
	reasonNoState    = "no-state"    // the template has no such state
	reasonRequires   = "requires"    // the host does not meet requires
	reasonHostAccess = "host-access" // needs -allow-host-access
	reasonOverCap    = "over-cap"    // over the -max-concurrent cap
	reasonCancelled  = "cancelled"   // interrupted before it started (or torn down by the interrupt)
	reasonAborted    = "aborted"     // not attempted: the command stopped on another target's error
	reasonLoad       = "load"        // the template failed to load
	reasonStart      = "start"       // could not be built, pulled or started
	reasonUnhealthy  = "unhealthy"   // started, but not ready / seed failed / verify failed
)

// outcomeEntry is one skipped or failed target in a -summary.
type outcomeEntry struct {
	ID     string `json:"id"`
	State  string `json:"state,omitempty"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
	// Cause and Missing say, for a requires skip, which requirement the host
	// does not meet (runner.Cause*) and what it lacks.
	Cause   string   `json:"cause,omitempty"`
	Missing []string `json:"missing,omitempty"`
}

// requiresSkip is the -summary entry of a target the host's requires
// preflight skipped.
func requiresSkip(id, state string, d runner.Decision) outcomeEntry {
	return outcomeEntry{ID: id, State: state, Reason: reasonRequires, Detail: d.Reason, Cause: d.Cause, Missing: d.Missing}
}

// runSummary is `run -json -summary`: what started, what failed and what was
// skipped, so a pipeline can tell the three apart (a target in none of them
// was not selected). A target that started but is not confirmed in its state
// is in targets (it is running) and in failed (it fails the run).
type runSummary struct {
	Targets []*runner.Handle `json:"targets"`
	Failed  []outcomeEntry   `json:"failed"`
	Skipped []outcomeEntry   `json:"skipped"`
}

func cmdRun() *Command {
	var sel, files multiFlag
	var flt filters
	var all, variants, detach, noVerify, noPull, noCache, force, summary bool
	var maxConcurrent int
	var targetsFile, platform, readyTimeout, nucleiDir string
	var ignoreRequires, allowHostAccess bool
	exp := runner.DefaultExposure()
	return &Command{
		Name:  "run",
		Short: "build if needed, then run target(s) in a state and verify them",
		Usage: "[vulnerable|patched] -t SEL... | -f FILE | <filter> | -all [-variants] [-expose MODE] [-detach] [-targets-file FILE]",
		Long: `Stands targets up (default state: vulnerable; give vulnerable or patched
anywhere among the arguments, e.g. ` + "`run grafana patched`" + `), waits until they are ready,
and runs each state's verify probes so you know the target is genuinely in the
declared state before you scan it. Many targets can run at once; each gets its
own IP on the internal network. Without -detach the command holds the batch
and tears it down on Ctrl-C.

Exposure modes:
  internal  (default) a Docker network, nothing published on the host. Run the
            scanner as a container on the same network, or scan the container
            IPs where the host can route to them.
  host      publish the port on the host (one host port serves one target).
  macvlan   give the target its own IP on the LAN (needs -parent IFACE).`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&sel, "t", "template selector: id, group handle, folder, file or suite:<name> (repeatable)")
			fs.Var(&files, "f", "read selectors from a file, one per line (# comments allowed); repeatable")
			fs.BoolVar(&all, "all", false, "run every template (one target per variant group; add -variants for the full matrix)")
			fs.BoolVar(&variants, "variants", false, "expand a selected group to all its members (and -all to every variant); a group selector alone runs only its primary")
			flt.register(fs)
			fs.IntVar(&maxConcurrent, "max-concurrent", DefaultMaxConcurrent, "cap on simultaneously running targets")
			addExposureFlags(fs, &exp)
			fs.StringVar(&targetsFile, "targets-file", "", "write the scannable target URLs here (one per line)")
			fs.BoolVar(&detach, "detach", false, "leave the targets running and exit")
			fs.BoolVar(&noVerify, "no-verify", false, "skip the verify probes")
			fs.BoolVar(&noPull, "no-pull", false, "never pull prebuilt images")
			fs.BoolVar(&noCache, "no-cache", false, "build without the layer cache")
			fs.BoolVar(&force, "force", false, "rebuild images even when they exist")
			fs.StringVar(&platform, "platform", "", "target platform for builds, e.g. linux/amd64")
			fs.StringVar(&readyTimeout, "ready-timeout", "", "override every template's healthcheck timeout, e.g. 120s")
			fs.StringVar(&nucleiDir, "nuclei-templates", "", "nuclei-templates checkout used to resolve the scanner templates shown for each target")
			fs.BoolVar(&ignoreRequires, "ignore-requires", false, "run even when the host does not meet a target's requires (arch/kvm/host_os/cpu_flags; requires.probe is not run)")
			fs.BoolVar(&allowHostAccess, "allow-host-access", false, "honor a template's host device passthrough and elevated capabilities (host-access primitives; only for templates you trust)")
			fs.BoolVar(&summary, "summary", false, "with -json, print {targets, failed, skipped} instead of the bare array of started targets")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) (retErr error) {
			if summary && !g.JSON {
				return usageError{"-summary shapes the -json output; add -json"}
			}
			// sum collects every selected target's fate for -summary. Once the
			// selection is resolved the -json output (the summary, or the bare
			// array of started targets) is emitted on every way out (success,
			// failure, interrupt) except a usage error, so a pipeline always
			// gets a document to parse.
			sum := runSummary{Targets: []*runner.Handle{}, Failed: []outcomeEntry{}, Skipped: []outcomeEntry{}}
			resolved, emitted := false, false
			emitOutput := func() error {
				emitted = true
				if summary {
					return g.emitJSON(sum)
				}
				return g.emitJSON(sum.Targets)
			}
			defer func() {
				var ue usageError
				if g.JSON && resolved && !emitted && !errors.As(retErr, &ue) {
					retErr = errors.Join(retErr, emitOutput())
				}
			}()
			skip := func(cs []*contract.Contract, state, reason, detail string) {
				for _, c := range cs {
					sum.Skipped = append(sum.Skipped, outcomeEntry{ID: c.ID(), State: state, Reason: reason, Detail: detail})
				}
			}
			// Flag mistakes are usage errors (exit 2), caught before any
			// template is resolved or image pulled/built.
			switch exp.Mode {
			case runner.ModeInternal, runner.ModeHost, runner.ModeMacvlan:
			default:
				return usageError{fmt.Sprintf("unknown -expose mode %q (internal, host or macvlan)", exp.Mode)}
			}
			if err := checkScannerDir("-nuclei-templates", nucleiDir); err != nil {
				return err
			}
			if maxConcurrent < 1 {
				return usageError{fmt.Sprintf("-max-concurrent must be at least 1, got %d", maxConcurrent)}
			}
			pinned := exp.HostPort != 0 || len(exp.HostPortMap) > 0
			if exp.HostPort < 0 || exp.HostPort > 65535 {
				return usageError{fmt.Sprintf("-host-port must be 1..65535, got %d", exp.HostPort)}
			}
			if pinned && exp.Mode != runner.ModeHost {
				return usageError{"-host-port / -host-port-map need -expose host"}
			}
			// Flags of another exposure mode would be silently ignored.
			if exp.Mode != runner.ModeHost && flagSet(fs, "bind") {
				return usageError{fmt.Sprintf("-bind is used only by -expose host (the mode is %s)", exp.Mode)}
			}
			if exp.Mode != runner.ModeMacvlan {
				for _, name := range []string{"parent", "ip", "subnet", "gateway"} {
					if flagSet(fs, name) {
						return usageError{fmt.Sprintf("-%s is used only by -expose macvlan (the mode is %s)", name, exp.Mode)}
					}
				}
			}
			var readyTimeoutD time.Duration
			if readyTimeout != "" {
				d, err := contract.ParseDuration(readyTimeout, 0)
				if err != nil {
					return usageError{"-ready-timeout: " + err.Error()}
				}
				readyTimeoutD = d
			}
			state, args, err := takeState(args)
			if err != nil {
				return err
			}
			if state == "" {
				state = contract.StateVulnerable
			}
			sel = append(sel, args...)
			store, err := g.Store()
			if err != nil {
				return err
			}
			cs, loadErrs, err := gatherSet(ctx, store, sel, files, all, variants, flt)
			if err != nil {
				return err
			}
			resolved = true
			if len(loadErrs) > 0 {
				for _, e := range loadErrs {
					g.errorf("ERROR %v\n", e)
					sum.Failed = append(sum.Failed, outcomeEntry{ID: loadErrID(e), Reason: reasonLoad, Detail: e.Error()})
				}
				skip(cs, state, reasonAborted, "not attempted: other templates failed to load")
				return fmt.Errorf("%d template(s) failed to load", len(loadErrs))
			}
			var runnable []*contract.Contract
			for _, c := range cs {
				if c.HasState(state) {
					runnable = append(runnable, c)
				} else {
					g.printf("skip %s: no %q state\n", c.ID(), state)
					skip([]*contract.Contract{c}, state, reasonNoState, fmt.Sprintf("no %q state", state))
				}
			}
			if len(runnable) == 0 {
				return fmt.Errorf("no templates have a %q state", state)
			}
			eng, err := g.Engine(ctx)
			if err != nil {
				skip(runnable, state, reasonAborted, err.Error())
				return err
			}
			r := runner.New(eng)
			host, herr := eng.Info(ctx)
			if herr != nil {
				skip(runnable, state, reasonAborted, herr.Error())
				return herr
			}

			// Drop what will not run here (requires, host access) before the
			// concurrency cap, so a skipped target never takes a slot.
			var skippedReq, skippedHost []string
			platformFor := map[*contract.Contract]string{}
			eligible := runnable[:0:0]
			pf := &preflighter{ctx: ctx, g: g, eng: eng, host: host, noPull: noPull, noRead: ignoreRequires}
			for _, c := range runnable {
				if !c.Requires.Empty() {
					d := pf.decide(c.Requires)
					switch {
					case d.Skip() && !ignoreRequires:
						g.printf("skip %s: %s\n", c.ID(), d.Reason)
						skippedReq = append(skippedReq, c.ID())
						sum.Skipped = append(sum.Skipped, requiresSkip(c.ID(), state, d))
						continue
					case d.Skip() && ignoreRequires:
						g.printf("%s does not meet requires (%s) -- running anyway (-ignore-requires)\n", c.ID(), d.Reason)
					case d.Action == runner.ActionEmulated:
						g.printf("%s: %s\n", c.ID(), d.Reason)
						platformFor[c] = d.Platform
					}
				}
				if !allowHostAccess {
					if reason := runner.HostAccessReason(c); reason != "" {
						g.printf("skip %s: needs host access (%s) -- re-run with -allow-host-access to include it\n", c.ID(), reason)
						skippedHost = append(skippedHost, c.ID())
						skip([]*contract.Contract{c}, state, reasonHostAccess, reason)
						continue
					}
				}
				eligible = append(eligible, c)
			}
			runnable = eligible

			// Concurrency cap: containers this batch replaces (same name) are not net new.
			batch := map[string]bool{}
			for _, c := range runnable {
				batch[c.ContainerName(state)] = true
			}
			already, err := r.Running(ctx, exp.Network)
			if err != nil {
				skip(runnable, state, reasonAborted, err.Error())
				return fmt.Errorf("count running targets for -max-concurrent: %w", err)
			}
			netNew := 0
			for _, t := range already {
				if !batch[t.Container] {
					netNew++
				}
			}
			free := maxConcurrent - netNew
			if free < 0 {
				free = 0
			}
			var overCap []*contract.Contract
			if len(runnable) > free {
				capDetail := fmt.Sprintf("over the -max-concurrent %d cap (%d already running)", maxConcurrent, netNew)
				if free == 0 {
					skip(runnable, state, reasonOverCap, capDetail)
					return fmt.Errorf("max concurrent (%d) already reached: %d target(s) running. bring some down first:  vulnsuite stop", maxConcurrent, netNew)
				}
				overCap, runnable = runnable[free:], runnable[:free]
				skip(overCap, state, reasonOverCap, capDetail)
				g.printf("max concurrent is %d (%d already running): starting %d, skipping %d.\n", maxConcurrent, netNew, len(runnable), len(overCap))
				g.printf("  raise it with -max-concurrent, or run the rest after `vulnsuite stop`.\n\n")
			}
			// Single-target pins are judged on what will actually start, after
			// the requires/host-access skips and the cap: a batch that ends up
			// with one target keeps its pin, and a pin that would have to serve
			// several targets is refused rather than silently dropped.
			multi := len(runnable) > 1
			if multi && exp.Mode == runner.ModeMacvlan && exp.IP != "" {
				return usageError{fmt.Sprintf("-ip pins one address but %d targets would start (%s); run one template at a time in macvlan mode, or omit -ip", len(runnable), contractIDs(runnable))}
			}
			if multi && pinned {
				return usageError{fmt.Sprintf("-host-port / -host-port-map pin one target's ports but %d targets would start (%s); select one target, or omit them for free ports", len(runnable), contractIDs(runnable))}
			}
			if len(runnable) == 1 && len(exp.HostPortMap) > 0 {
				if err := checkHostPortMap(exp.HostPortMap, runnable[0]); err != nil {
					return err
				}
			}

			opts := runner.Options{Verify: !noVerify, AllowHostAccess: allowHostAccess, IgnoreRequires: ignoreRequires, Build: builder.Options{Pull: !noPull, NoCache: noCache, Force: force, Platform: platform}}
			opts.ReadyTimeout = readyTimeoutD
			if !g.JSON && !g.Quiet {
				opts.Build.Output = g.Stdout
			}
			// The index only feeds the "scanner templates" lines, which -q
			// does not print: skip indexing the checkout then.
			var idx *scanners.Index
			if dir := scanners.ResolveDir(nucleiDir); dir != "" && !g.Quiet {
				if idx, err = loadNucleiIndex(dir); err != nil {
					return err
				}
			}
			var handles []*runner.Handle
			var failures []string
			// unhealthy: targets that came up but must not be handed out as-is
			// (not ready, a seed failed, or verify failed). They fail the run.
			var unhealthy []string
			cancelled := false
			// attempted counts the targets the loop reached; on an interrupt
			// the rest never started.
			attempted := 0
			for _, c := range runnable {
				if ctx.Err() != nil {
					cancelled = true
					break
				}
				attempted++
				if multi {
					g.printf("\n=== [%s] %s ===\n", c.ID(), state)
				} else {
					g.printf("[%s] %s: %s\n", c.ID(), state, c.Metadata.Summary)
				}
				tgtOpts := opts
				if p := platformFor[c]; p != "" && tgtOpts.Build.Platform == "" {
					tgtOpts.Build.Platform = p
				}
				g.printf("resolving image (%s)...\n", c.BuildKind(state))
				h, err := r.Run(ctx, c, state, exp, tgtOpts)
				if err != nil {
					if ctx.Err() != nil {
						attempted-- // cut short by the interrupt: it never started
						cancelled = true
						break
					}
					// requires.probe: the host lacks something; a skip, not a failure.
					if se, ok := runner.AsSkip(err); ok {
						g.printf("skip %s: %s\n", c.ID(), se.Decision.Reason)
						skippedReq = append(skippedReq, c.ID())
						sum.Skipped = append(sum.Skipped, requiresSkip(c.ID(), state, se.Decision))
						continue
					}
					g.errorf("  could not run %s: %v\n", c.ID(), err)
					failures = append(failures, c.ID())
					sum.Failed = append(sum.Failed, outcomeEntry{ID: c.ID(), State: state, Reason: reasonStart, Detail: err.Error()})
					continue
				}
				handles = append(handles, h)
				if ctx.Err() != nil {
					cancelled = true
					break
				}
				verb := "reused"
				switch {
				case h.Image.Built:
					verb = "built"
				case h.Image.Pulled:
					verb = "pulled"
				}
				g.printf("  image: %s (%s)\n", h.Image.Ref, verb)
				if !h.Ready {
					why := h.ReadyDetail
					if why == "" {
						why = "the healthcheck did not pass in time"
					}
					g.printf("  ready: NO -- %s\n", strings.ReplaceAll(why, "\n", "\n      "))
				}
				if noVerify {
					// verify folds seed failures into its detail; without it, say so here.
					for _, sr := range h.Seeds {
						if !sr.OK {
							g.printf("  seed: FAILED -- %q: %s\n", sr.Run, sr.Error)
						}
					}
				}
				reportVerify(g, h, "  ")
				if p := h.Problem(); p != "" {
					unhealthy = append(unhealthy, fmt.Sprintf("%s [%s] (%s)", c.ID(), state, p))
					sum.Failed = append(sum.Failed, outcomeEntry{ID: c.ID(), State: state, Reason: reasonUnhealthy, Detail: p})
				}
				g.printf("  scanner templates:\n")
				for _, line := range scanners.Match(c, idx).Lines(c) {
					g.printf("  %s\n", line)
				}
			}
			if cancelled {
				// Interrupted: this batch never got handed out, so tear down what
				// it started rather than leave half a batch behind.
				g.errorf("\ninterrupted: tearing down %d started target(s)...\n", len(handles))
				// Everything this batch reached is torn down, and the rest never
				// started: all of it is cancelled, none of it is running.
				for _, h := range handles {
					sum.Skipped = append(sum.Skipped, outcomeEntry{ID: h.ID, State: h.State, Reason: reasonCancelled, Detail: "started, then torn down by the interrupt"})
				}
				skip(runnable[attempted:], state, reasonCancelled, "interrupted before it started")
				if err := teardown(ctx, g, r, handles); err != nil {
					return err
				}
				return errInterrupted
			}
			if len(handles) == 0 {
				if len(skippedHost) > 0 {
					return fmt.Errorf("nothing came up: %d target(s) need -allow-host-access (%s)", len(skippedHost), strings.Join(skippedHost, ", "))
				}
				return fmt.Errorf("nothing came up")
			}

			sum.Targets = append(sum.Targets, handles...)
			switch {
			case g.JSON:
				if err := emitOutput(); err != nil {
					return err
				}
			default:
				// The URLs are the command's output: -q drops the header and
				// the hints, never the list (as with `vulnsuite -q targets`).
				out := func(format string, a ...any) { fmt.Fprintf(g.Stdout, format, a...) }
				g.printf("\nScan these with your probe:\n")
				for _, h := range handles {
					extra := ""
					if h.Exposure.Mode == runner.ModeInternal && h.IP != "" {
						extra = fmt.Sprintf("  (ip %s)", h.IP)
					}
					pts := h.PortTargets()
					if len(pts) == 0 {
						out("  %-52s %s%s\n", fmt.Sprintf("%s [%s]", h.ID, h.State), h.ScannerTarget(), extra)
						continue
					}
					for _, pt := range pts {
						tag := fmt.Sprintf("%s [%s]", h.ID, h.State)
						note := extra
						if len(pts) > 1 {
							note = fmt.Sprintf("  (container port %d)%s", pt.ContainerPort, extra)
						}
						out("  %-52s %s%s\n", tag, pt.URL, note)
					}
				}
				if handles[0].Exposure.Mode == runner.ModeInternal {
					g.printf("\n  run your scanner on the same network, e.g.:\n")
					g.printf("    docker run --rm --network %s projectdiscovery/nuclei -u %s\n", exp.Network, handles[0].ScannerTarget())
					g.printf("  or write the IP list:  vulnsuite targets -file targets.txt\n")
				}
			}
			if targetsFile != "" {
				var lines []string
				for _, h := range handles {
					pts := h.PortTargets()
					if len(pts) <= 1 {
						lines = append(lines, scanURL(h))
						continue
					}
					for _, pt := range pts {
						lines = append(lines, pt.URL)
					}
				}
				if err := os.WriteFile(targetsFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
					return err
				}
				g.printf("\nwrote %s (%d targets)\n", targetsFile, len(lines))
			}
			if len(failures) > 0 {
				g.errorf("\n%d failed to start: %s\n", len(failures), strings.Join(failures, ", "))
			}
			if len(unhealthy) > 0 {
				g.errorf("\n%d not confirmed in the requested state: %s\n", len(unhealthy), strings.Join(unhealthy, ", "))
			}
			runErr := func() error {
				if n := len(failures) + len(unhealthy); n > 0 {
					return fmt.Errorf("%d target(s) failed", n)
				}
				return nil
			}
			if len(skippedReq) > 0 {
				g.printf("\n%d skipped (host does not meet requires): %s\n", len(skippedReq), strings.Join(skippedReq, ", "))
				g.printf("  override with -ignore-requires, or run on a matching host.\n")
			}
			if len(skippedHost) > 0 {
				g.printf("\n%d skipped (needs host access): %s\n", len(skippedHost), strings.Join(skippedHost, ", "))
				g.printf("  these request host devices or elevated capabilities; if you trust them, re-run with -allow-host-access.\n")
			}
			if len(overCap) > 0 {
				g.printf("\n%d not started (over the -max-concurrent %d cap): %s\n", len(overCap), maxConcurrent, contractIDs(overCap))
			}
			if !g.JSON {
				g.printf("\nTear down:  vulnsuite stop   (brings down all %d target(s))\n", len(handles))
			}
			if detach {
				return runErr()
			}
			g.printf("\nHolding. Ctrl-C to tear down this batch.\n")
			sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			<-sigCtx.Done()
			// Release the handler at once: a second Ctrl-C during teardown then
			// terminates the process (main releases its own on the first).
			stop()
			g.printf("\ntearing down...\n")
			return errors.Join(runErr(), teardown(ctx, g, r, handles))
		},
	}
}

// contractIDs joins the contracts' ids for messages.
func contractIDs(cs []*contract.Contract) string {
	ids := make([]string, 0, len(cs))
	for _, c := range cs {
		ids = append(ids, c.ID())
	}
	return strings.Join(ids, ", ")
}

// errInterrupted reports a run cut short by Ctrl-C / SIGTERM.
var errInterrupted = errors.New("interrupted")

// teardown removes the handles' containers on a fresh context bounded by
// runner.CleanupTimeout (the run's own context is usually cancelled by now),
// reporting every removal that failed.
func teardown(ctx context.Context, g *Global, r *runner.Runner, handles []*runner.Handle) error {
	cctx, cancel := runner.CleanupContext(ctx)
	defer cancel()
	var failed []string
	for _, h := range handles {
		if err := r.Stop(cctx, h); err != nil {
			g.errorf("  could not tear down %s [%s]: %v\n", h.ID, h.State, err)
			failed = append(failed, h.Container)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("teardown: %d target(s) not fully removed (%s); remove them with:  vulnsuite stop", len(failed), strings.Join(failed, ", "))
	}
	return nil
}

// reportableHostIP turns a binding's host IP into one a scanner can dial.
// A port published on all interfaces (empty, 0.0.0.0 or ::) is reachable via
// loopback, which is what a local scanner should use; an explicit -bind
// address is carried through unchanged so a remote daemon's address survives.
func reportableHostIP(ip string) string {
	switch ip {
	case "", "0.0.0.0", "::":
		return "127.0.0.1"
	}
	return ip
}

// hostPortsLabel renders a target's published host ports as "39841,39842", or
// "-" when none are published (internal/macvlan mode).
func hostPortsLabel(t runner.Target) string {
	var ps []string
	for _, p := range t.Ports {
		if p.HostPort > 0 {
			ps = append(ps, strconv.Itoa(p.HostPort))
		}
	}
	if len(ps) == 0 {
		return "-"
	}
	return strings.Join(ps, ",")
}

// scanURL prefers the container IP for internal mode (what a host-side
// scanner can use when the host routes to the Docker network).
func scanURL(h *runner.Handle) string {
	if h.Exposure.Mode == runner.ModeInternal && h.IP != "" {
		return runner.FormatTarget(h.Scheme, h.IP, h.EndpointPort)
	}
	return h.ScannerTarget()
}

// -- stop ---------------------------------------------------------------------

func cmdStop() *Command {
	var sel multiFlag
	var network string
	var pruneNet, variantsStop bool
	return &Command{
		Name: "stop", Aliases: []string{"down"},
		Short: "tear down running targets (all, or selected templates)",
		Usage: "[-t SELECTOR]... [-variants] [-prune-net]",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&sel, "t", "only this template/selector (repeatable; default: everything vulnsuite started)")
			fs.StringVar(&network, "network", runner.DefaultNetwork, "internal network name")
			fs.BoolVar(&variantsStop, "variants", false, "when a selector names a group, stop every member (default: just its primary)")
			fs.BoolVar(&pruneNet, "prune-net", false, "also remove the internal network when stopping everything")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			sel = append(sel, args...)
			if pruneNet && len(sel) > 0 {
				return usageError{"-prune-net removes the network only when stopping everything; drop the selectors, or run `vulnsuite stop -prune-net` once the rest is down"}
			}
			eng, err := g.Engine(ctx)
			if err != nil {
				return err
			}
			r := runner.New(eng)
			var ids []string
			var stopErrs []error
			if len(sel) > 0 {
				store, err := g.Store()
				if err != nil {
					return err
				}
				cs, loadErrs, err := gather(store, sel, false, variantsStop)
				if err != nil {
					return err
				}
				for _, c := range cs {
					ids = append(ids, c.ID())
				}
				// A template that no longer loads (broken after an update,
				// say) may still have a target running: stop it by the id
				// its contract declares. Only when even that is unreadable
				// is it an error, never a silent "nothing to stop".
				for _, le := range loadErrs {
					var e *loader.Error
					id := ""
					if errors.As(le, &e) {
						id = loader.PeekID(e.Path)
					}
					if id == "" {
						stopErrs = append(stopErrs, le)
						continue
					}
					g.errorf("warning: %v; stopping %s by its declared id\n", le, id)
					ids = append(ids, id)
				}
				if len(ids) == 0 {
					return errors.Join(stopErrs...)
				}
			} else {
				ids = []string{""}
			}
			removed := []string{} // -json prints [] (not null) when nothing ran
			for _, id := range ids {
				names, err := r.StopAll(ctx, id)
				removed = append(removed, names...)
				if err != nil {
					stopErrs = append(stopErrs, err)
				}
			}
			// Prune before reporting, so -json carries the outcome too. A network
			// that cannot be removed (still in use, already gone) is a warning,
			// not a failed stop.
			networkRemoved := false
			var pruneErr error
			if pruneNet && len(sel) == 0 {
				if pruneErr = r.PruneNetwork(ctx, network); pruneErr == nil {
					networkRemoved = true
				}
			}
			if g.JSON {
				if err := g.emitJSON(map[string]any{"removed": removed, "network_removed": networkRemoved}); err != nil {
					return err
				}
			} else if len(removed) == 0 {
				g.printf("nothing to stop\n")
			} else {
				g.printf("stopped %d container(s):\n", len(removed))
				for _, n := range removed {
					g.printf("  %s\n", n)
				}
			}
			switch {
			case networkRemoved:
				g.printf("removed network %s\n", network)
			case pruneErr != nil:
				g.errorf("could not remove network %s: %v\n", network, pruneErr)
			}
			return errors.Join(stopErrs...)
		},
	}
}

// -- ps -----------------------------------------------------------------------

func cmdPS() *Command {
	var network string
	return &Command{
		Name:  "ps",
		Short: "show running targets (id, state, ip)",
		Usage: "",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&network, "network", runner.DefaultNetwork, "internal network name")
		},
		NoArgs: true,
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			eng, err := g.Engine(ctx)
			if err != nil {
				return err
			}
			rows, err := runner.New(eng).Running(ctx, network)
			if err != nil {
				return err
			}
			if g.JSON {
				if rows == nil {
					rows = []runner.Target{}
				}
				return g.emitJSON(rows)
			}
			if len(rows) == 0 {
				g.printf("no targets running.  start some with:  vulnsuite run -t <selector>\n")
				return nil
			}
			tw := tabwriter.NewWriter(g.Stdout, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTATE\tIP\tHOST PORTS\tSTATUS")
			for _, r := range rows {
				ip := r.IP
				if ip == "" {
					ip = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.State, ip, hostPortsLabel(r), r.Status)
			}
			tw.Flush()
			g.printf("\n%d running\n", len(rows))
			return nil
		},
	}
}

// -- targets ------------------------------------------------------------------

func cmdTargets() *Command {
	var file, by, network string
	return &Command{
		Name:  "targets",
		Short: "print the running targets' scannable URLs (right port per template)",
		Usage: "[-file FILE] [-by ip|alias|host]",
		Long: `Reads each running container's address and its template's real port, so the
list is always correct for what is up. Scan exactly these instead of sweeping
the subnet. Non-HTTP targets come out as host:port for network templates.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "file", "", "write the URL list here (nuclei -l <file>)")
			fs.StringVar(&by, "by", "auto", "address targets by: auto (published host binding if any, else container ip), ip, alias, or host")
			fs.StringVar(&network, "network", runner.DefaultNetwork, "internal network name")
		},
		NoArgs: true,
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) (retErr error) {
			switch by {
			case "auto", "ip", "alias", "host":
			default:
				return usageError{fmt.Sprintf("unknown -by %q (auto, ip, alias or host)", by)}
			}
			type pair struct {
				ID    string `json:"id"`
				State string `json:"state"`
				URL   string `json:"url"`
			}
			// With -json the list is printed on every way out but a usage
			// error, like ps -json: [] when nothing is running or the engine
			// is unreachable, the URLs resolved so far on a later failure.
			pairs := []pair{}
			emitted := false
			defer func() {
				if g.JSON && !emitted {
					retErr = errors.Join(retErr, g.emitJSON(pairs))
				}
			}()
			eng, err := g.Engine(ctx)
			if err != nil {
				return err
			}
			rows, err := runner.New(eng).Running(ctx, network)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				return fmt.Errorf("no targets running.  start some with:  vulnsuite run -t <selector>")
			}
			// The published ports and schemes come from the container (recorded
			// at run time), so a target whose template is outside the templates
			// root, or no longer loads, is still addressable. Only containers
			// from before that label fall back to the templates store.
			var byID map[string]*contract.Contract
			var storeRoot string
			var storeErr error
			loaded := false
			portsOf := func(r runner.Target) ([]runner.PublishedPort, error) {
				if r.Published != nil {
					return r.Published, nil
				}
				if !loaded {
					loaded = true
					store, err := g.Store()
					if err == nil {
						storeRoot = store.Root
						byID, err = store.ByID()
					}
					storeErr = err
				}
				if storeErr != nil {
					return nil, fmt.Errorf("no ports recorded on the container and the templates store is unavailable: %v", storeErr)
				}
				c, ok := byID[r.ID]
				if !ok {
					return nil, fmt.Errorf("no ports recorded on the container and the template is not in %s", storeRoot)
				}
				var out []runner.PublishedPort
				for _, pp := range c.Service.HostPublishPorts() {
					out = append(out, runner.PublishedPort{ContainerPort: pp.Container, Scheme: pp.Scheme()})
				}
				return out, nil
			}
			unresolved, noAddr := 0, 0
			for _, r := range rows {
				published, err := portsOf(r)
				if err != nil {
					g.errorf("skip %s [%s]: %v (restart it with `vulnsuite run` to record its ports)\n", r.ID, r.State, err)
					unresolved++
					continue
				}
				before := len(pairs)
				// host mode (explicit, or auto when the target has host bindings):
				// one row per actual host binding, primary first.
				if by == "host" || (by == "auto" && len(r.Ports) > 0) {
					bind := map[int]runner.PublishedPort{}
					for _, pb := range r.Ports {
						bind[pb.ContainerPort] = pb
					}
					for _, pp := range published {
						pb, ok := bind[pp.ContainerPort]
						if !ok {
							continue
						}
						pairs = append(pairs, pair{r.ID, r.State,
							runner.FormatTarget(pp.Scheme, reportableHostIP(pb.HostIP), pb.HostPort)})
					}
				} else {
					// alias / ip (and auto with no host bindings): address each
					// published container port at the alias or container IP.
					for _, pp := range published {
						host := r.IP
						if by == "alias" {
							host = runner.TargetAlias(r.ID, r.State)
						}
						if host == "" {
							continue
						}
						pairs = append(pairs, pair{r.ID, r.State, runner.FormatTarget(pp.Scheme, host, pp.ContainerPort)})
					}
				}
				if len(pairs) == before {
					noAddr++
				}
			}
			if len(pairs) == 0 {
				var why []string
				if unresolved > 0 {
					why = append(why, fmt.Sprintf("%d with no known ports (see above)", unresolved))
				}
				if noAddr > 0 {
					hint := "no container ip on the network; try -by alias"
					switch by {
					case "host":
						hint = "not published on the host; run with -expose host, or use -by ip / -by alias"
					case "alias":
						hint = "no published ports"
					}
					why = append(why, fmt.Sprintf("%d with no address -by %s (%s)", noAddr, by, hint))
				}
				return fmt.Errorf("no scannable address for the %d running target(s): %s", len(rows), strings.Join(why, "; "))
			}
			// -file is written whatever the output format, so
			// `vulnsuite -json targets -file F && nuclei -l F` works.
			if file != "" {
				var lines []string
				for _, p := range pairs {
					lines = append(lines, p.URL)
				}
				if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
					return err
				}
			}
			if g.JSON {
				emitted = true
				return g.emitJSON(pairs)
			}
			if file != "" {
				g.printf("wrote %s (%d targets, by %s)\nscan exactly these (no subnet sweep):\n  nuclei -l %s\n", file, len(pairs), by, file)
				return nil
			}
			// The URL list is this command's output, not progress: -q keeps it
			// and silences only the hint below.
			for _, p := range pairs {
				fmt.Fprintf(g.Stdout, "%-48s # %s %s\n", p.URL, p.ID, p.State)
			}
			g.printf("\n%d targets. Scan just these instead of the subnet, e.g.:\n  vulnsuite targets -file targets.txt && nuclei -l targets.txt\n", len(pairs))
			return nil
		},
	}
}
