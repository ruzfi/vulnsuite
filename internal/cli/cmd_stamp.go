package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/runner"
)

// stampStateResult is one state's run in a stamp.
type stampStateResult struct {
	State  string `json:"state"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	// skip is set when requires.probe found the host lacking: the target is
	// skipped, not failed.
	skip string
}

// stampResult is one target's outcome in `stamp -json`. Outcome is stamped
// (verified_on written), verified (all ok, -dry-run), failed or skipped.
type stampResult struct {
	ID         string               `json:"id"`
	Path       string               `json:"path,omitempty"`
	Outcome    string               `json:"outcome"`
	Detail     string               `json:"detail,omitempty"`
	States     []stampStateResult   `json:"states"`
	VerifiedOn *contract.VerifiedOn `json:"verified_on,omitempty"`
}

// Stamp outcomes.
const (
	stampStamped  = "stamped"
	stampVerified = "verified"
	stampFailed   = "failed"
	stampSkipped  = "skipped"
)

func cmdStamp() *Command {
	var sel, files multiFlag
	var flt filters
	var all, variants, noPull, noCache, force, allowHostAccess, dryRun bool
	var readyTimeout string
	exp := runner.DefaultExposure()
	return &Command{
		Name:  "stamp",
		Short: "run every state of target(s) and record metadata.verified_on when all verify ok",
		Usage: "-t SEL... | -f FILE | <filter> | -all [-variants] [-dry-run] [-expose MODE]",
		Long: `Turns "nobody has run this" into recorded evidence. For each selected
template, stamp runs every declared state in turn (build, start, verify, tear
down) and, only when every state printed verify: ok, writes
metadata.verified_on into the contract file:

  verified_on:
    date: "2026-11-21"           # the day of the run (UTC)
    vulnsuite: v0.4.0            # this binary's version
    host: linux/amd64            # the container daemon's os/arch
    platform: linux/amd64        # only when the image ran under emulation
    cpu_flags: [avx512vbmi]      # the requires.cpu_flags the host was checked to have
    states: [vulnerable, patched]

and sets verification: verified. Only those lines change; comments and the
rest of the file are kept. When any state fails, or the host does not meet
the template's requires, the file is left untouched.

A stamp is evidence that a host meeting the requires ran the target, so there
is no -ignore-requires here. -dry-run runs and verifies without writing.
Targets run one at a time, and each state is torn down before the next.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&sel, "t", "template selector: id, group handle, folder, file or suite:<name> (repeatable)")
			fs.Var(&files, "f", "read selectors from a file, one per line (# comments allowed); repeatable")
			fs.BoolVar(&all, "all", false, "stamp every template (one per variant group; add -variants for all)")
			fs.BoolVar(&variants, "variants", false, "expand a selected group to all its members")
			flt.register(fs)
			addExposureFlags(fs, &exp)
			fs.BoolVar(&dryRun, "dry-run", false, "run and verify every state, but do not write verified_on")
			fs.BoolVar(&noPull, "no-pull", false, "never pull prebuilt images")
			fs.BoolVar(&noCache, "no-cache", false, "build without the layer cache")
			fs.BoolVar(&force, "force", false, "rebuild images even when they exist")
			fs.StringVar(&readyTimeout, "ready-timeout", "", "override every template's healthcheck timeout, e.g. 120s")
			fs.BoolVar(&allowHostAccess, "allow-host-access", false, "honor a template's host device passthrough and elevated capabilities (only for templates you trust)")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) (retErr error) {
			if _, err := checkExposureFlags(fs, exp); err != nil {
				return err
			}
			if exp.Mode == runner.ModeMacvlan && exp.IP != "" {
				return usageError{"-ip pins one address, but stamp starts each state in turn; omit it"}
			}
			readyTimeoutD, err := parseReadyTimeout(readyTimeout)
			if err != nil {
				return err
			}
			if state, _, _ := takeState(args); state != "" {
				return usageError{fmt.Sprintf("stamp runs every declared state; drop %q", state)}
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
			results := []stampResult{}
			defer func() {
				if g.JSON {
					retErr = errors.Join(retErr, g.emitJSON(results))
				}
			}()
			if len(loadErrs) > 0 {
				for _, e := range loadErrs {
					g.errorf("ERROR %v\n", e)
				}
				return fmt.Errorf("%d template(s) failed to load", len(loadErrs))
			}
			eng, err := g.Engine(ctx)
			if err != nil {
				return err
			}
			host, err := eng.Info(ctx)
			if err != nil {
				return err
			}
			r := runner.New(eng)
			pf := &preflighter{ctx: ctx, g: g, eng: eng, host: host, noPull: noPull}
			opts := runner.Options{Verify: true, AllowHostAccess: allowHostAccess, ReadyTimeout: readyTimeoutD,
				Build: builder.Options{Pull: !noPull, NoCache: noCache, Force: force}}
			if !g.JSON && !g.Quiet {
				opts.Build.Output = g.Stdout
			}
			for _, c := range cs {
				if ctx.Err() != nil {
					return errInterrupted
				}
				res := stampOne(ctx, g, r, pf, c, exp, opts)
				if res.Outcome == stampVerified && !dryRun {
					if werr := contract.StampFile(c.SourcePath, *res.VerifiedOn); werr != nil {
						res.Outcome, res.Detail = stampFailed, "verified, but could not write verified_on: "+werr.Error()
					} else {
						res.Outcome = stampStamped
					}
				}
				results = append(results, res)
				switch res.Outcome {
				case stampStamped:
					g.printf("stamped %s: %s\n", c.ID(), c.SourcePath)
				case stampVerified:
					g.printf("verified %s (-dry-run: %s not written)\n", c.ID(), c.SourcePath)
				case stampSkipped:
					g.printf("skip %s: %s\n", c.ID(), res.Detail)
				default:
					g.errorf("not stamped %s: %s\n", c.ID(), res.Detail)
				}
				if ctx.Err() != nil {
					return errInterrupted
				}
			}
			var failed, skipped []string
			for _, res := range results {
				switch res.Outcome {
				case stampFailed:
					failed = append(failed, res.ID)
				case stampSkipped:
					skipped = append(skipped, res.ID)
				}
			}
			if len(skipped) > 0 {
				g.printf("\n%d skipped (not stamped): %s\n", len(skipped), strings.Join(skipped, ", "))
			}
			if len(failed) > 0 {
				return fmt.Errorf("%d target(s) not stamped: %s", len(failed), strings.Join(failed, ", "))
			}
			return nil
		},
	}
}

// stampOne runs every declared state of c and returns the outcome; on
// stampVerified, VerifiedOn holds the evidence to write.
func stampOne(ctx context.Context, g *Global, r *runner.Runner, pf *preflighter, c *contract.Contract,
	exp runner.Exposure, opts runner.Options) stampResult {
	res := stampResult{ID: c.ID(), Path: c.SourcePath, States: []stampStateResult{}}
	platform := ""
	if !c.Requires.Empty() {
		d := pf.decide(c.Requires)
		if d.Skip() {
			res.Outcome, res.Detail = stampSkipped, d.Reason
			return res
		}
		if d.Action == runner.ActionEmulated {
			g.printf("%s: %s\n", c.ID(), d.Reason)
			platform = d.Platform
			opts.Build.Platform = d.Platform
		}
	}
	if !opts.AllowHostAccess {
		if reason := runner.HostAccessReason(c); reason != "" {
			res.Outcome = stampSkipped
			res.Detail = "needs host access (" + reason + ") -- re-run with -allow-host-access to include it"
			return res
		}
	}
	states := c.DeclaredStates()
	for _, state := range states {
		g.printf("\n=== [%s] %s ===\n", c.ID(), state)
		sr := stampState(ctx, g, r, c, state, exp, opts)
		res.States = append(res.States, sr)
		if sr.skip != "" {
			res.Outcome, res.Detail = stampSkipped, sr.skip
			return res
		}
		if !sr.OK {
			res.Outcome, res.Detail = stampFailed, fmt.Sprintf("%s: %s", state, sr.Detail)
			return res
		}
	}
	res.Outcome = stampVerified
	res.VerifiedOn = &contract.VerifiedOn{
		Date:      time.Now().UTC().Format(time.DateOnly),
		Vulnsuite: resolvedVersion(),
		Host:      pf.host.OS + "/" + pf.host.Arch,
		Platform:  platform,
		CPUFlags:  append([]string(nil), c.Requires.CPUFlags...),
		States:    states,
	}
	return res
}

// stampState runs one state, reports its verify, and tears it down.
func stampState(ctx context.Context, g *Global, r *runner.Runner, c *contract.Contract, state string,
	exp runner.Exposure, opts runner.Options) stampStateResult {
	sr := stampStateResult{State: state}
	h, err := r.Run(ctx, c, state, exp, opts)
	if err != nil {
		if se, ok := runner.AsSkip(err); ok {
			sr.skip = se.Decision.Reason
			return sr
		}
		sr.Detail = "could not run: " + err.Error()
		return sr
	}
	defer func() {
		cctx, cancel := runner.CleanupContext(ctx)
		defer cancel()
		if err := r.Stop(cctx, h); err != nil {
			g.errorf("  could not tear down %s [%s]: %v (remove it with: vulnsuite stop)\n", h.ID, h.State, err)
		}
	}()
	reportVerify(g, h, "  ")
	switch {
	case h.Problem() != "":
		sr.Detail = h.Problem()
		if h.VerifyDetail != "" {
			sr.Detail += ": " + h.VerifyDetail
		}
	case h.VerifyOK == nil:
		sr.Detail = "verify skipped (" + h.VerifyDetail + "); a stamp needs every state verified"
	default:
		sr.OK = true
	}
	return sr
}
