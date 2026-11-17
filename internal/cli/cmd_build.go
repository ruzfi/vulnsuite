package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/loader"
	"github.com/ruzfi/vulnsuite/pkg/runner"
)

func parseStates(s string) ([]string, error) {
	switch s {
	case "", "all":
		return contract.StateNames, nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if !has(contract.StateNames, p) {
			return nil, usageError{fmt.Sprintf("unknown state %q (vulnerable, patched or all)", p)}
		}
		out = append(out, p)
	}
	return out, nil
}

// takeState pulls a state token (vulnerable or patched) out of a command's
// positionals, wherever it appears (`run grafana patched`, `build patched -t
// x`), and returns it with the remaining positionals, the selectors. A
// positional spelled like a state is always the state: no template in the
// community set has an id, group or category named vulnerable or patched, and
// one that did can still be selected with -t. Naming two different states is a
// usage error.
func takeState(args []string) (state string, rest []string, err error) {
	for _, a := range args {
		if !has(contract.StateNames, a) {
			rest = append(rest, a)
			continue
		}
		if state != "" && state != a {
			return "", nil, usageError{fmt.Sprintf("two states given (%s and %s); run one state at a time", state, a)}
		}
		state = a
	}
	return state, rest, nil
}

// flagSet reports whether the named flag was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// buildSummary is `build -json -summary`: the images resolved, the jobs that
// failed (load, build, pull or push errors) and the ones skipped, each with a
// reason, so a pipeline can tell the three apart.
type buildSummary struct {
	Built   []buildResult  `json:"built"`
	Failed  []buildResult  `json:"failed"`
	Skipped []outcomeEntry `json:"skipped"`
}

type buildResult struct {
	ID        string   `json:"id"`
	State     string   `json:"state"`
	Ref       string   `json:"ref,omitempty"`
	BuildKind string   `json:"build_kind,omitempty"`
	Built     bool     `json:"built"`
	Pulled    bool     `json:"pulled"`
	Pushed    []string `json:"pushed,omitempty"`
	Elapsed   string   `json:"elapsed,omitempty"`
	Error     string   `json:"error,omitempty"`
}

func cmdBuild() *Command {
	var sel, files multiFlag
	var flt filters
	var all, variants, noCache, force, noPull, push, showLog, ignoreRequires, summary bool
	var states, registry, platform string
	var jobs int
	return &Command{
		Name:  "build",
		Short: "build (or pull) the images for templates, content-addressed, in parallel",
		Usage: "[vulnerable|patched] -t SEL... | -f FILE | <filter> | -all [-variants] [-state vulnerable|patched|all] [-j N] [-push -registry REG]",
		Long: `Every state's image is tagged ` + contract.ImageRepoPrefix + `/<id>:<state>-<hash> where the hash
covers the base, patches, overlays and environment. Identical inputs are never
rebuilt. Prebuilt (image-kind) states are pulled, not built. A state
positional (vulnerable or patched), anywhere among the arguments, is shorthand
for -state: ` + "`build patched -t grafana`" + `.

With -push, each image is also tagged <registry>/<id>:<state> and
<registry>/<id>:<state>-<hash> and pushed. Credentials come from
~/.docker/config.json or VULNSUITE_REGISTRY_USER / VULNSUITE_REGISTRY_TOKEN.
The env pair is only sent when pushing, never on pulls of template images,
unless VULNSUITE_REGISTRY names a registry: then it is used for that registry
only (pulls and pushes).`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&sel, "t", "template selector: id, group handle, folder, file or suite:<name> (repeatable)")
			fs.Var(&files, "f", "read selectors from a file, one per line (# comments allowed); repeatable")
			fs.BoolVar(&all, "all", false, "build every template (one target per variant group; add -variants for the full matrix)")
			fs.BoolVar(&variants, "variants", false, "expand a selected group to all its members (and -all to every variant); a group selector alone builds only its primary")
			flt.register(fs)
			fs.StringVar(&states, "state", "all", "which states: vulnerable, patched, or all")
			fs.IntVar(&jobs, "j", defaultJobs(), "parallel builds")
			fs.BoolVar(&noCache, "no-cache", false, "disable the engine's layer cache")
			fs.BoolVar(&force, "force", false, "rebuild even when the content-addressed image exists")
			fs.BoolVar(&noPull, "no-pull", false, "never pull; fail if a prebuilt image is missing")
			fs.StringVar(&platform, "platform", "", "target platform, e.g. linux/amd64")
			fs.BoolVar(&push, "push", false, "push the images to -registry after building")
			fs.StringVar(&registry, "registry", "", "registry prefix for -push, e.g. ghcr.io/ruzfi/vulnsuite")
			fs.BoolVar(&showLog, "log", false, "print the full engine output of every build")
			fs.BoolVar(&ignoreRequires, "ignore-requires", false, "build even when the host does not meet a target's requires")
			fs.BoolVar(&summary, "summary", false, "with -json, print {built, failed, skipped} instead of the bare array of results")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			if summary && !g.JSON {
				return usageError{"-summary shapes the -json output; add -json"}
			}
			posState, args, err := takeState(args)
			if err != nil {
				return err
			}
			sel = append(sel, args...)
			want, err := parseStates(states)
			if err != nil {
				return err
			}
			if posState != "" {
				// `build patched ...` is -state patched; an explicit -state
				// that says otherwise is a contradiction, not a preference.
				if flagSet(fs, "state") && (len(want) != 1 || want[0] != posState) {
					return usageError{fmt.Sprintf("state %q contradicts -state %s", posState, states)}
				}
				want = []string{posState}
			}
			if push && registry == "" {
				return usageError{"-push needs -registry"}
			}
			store, err := g.Store()
			if err != nil {
				return err
			}
			cs, loadErrs, err := gatherSet(ctx, store, sel, files, all, variants, flt)
			if err != nil {
				return err
			}
			// A template that fails to load is a failed build, not a silent
			// skip: report it, carry it into the results, and exit non-zero.
			var loadFailed []buildResult
			for _, e := range loadErrs {
				g.errorf("ERROR %v\n", e)
				loadFailed = append(loadFailed, buildResult{ID: loadErrID(e), Error: e.Error()})
			}
			skipped := []outcomeEntry{}
			var jobsList []builder.Job
			for _, c := range cs {
				n := 0
				for _, s := range want {
					if c.HasState(s) {
						jobsList = append(jobsList, builder.Job{Contract: c, State: s})
						n++
					}
				}
				if n == 0 {
					skipped = append(skipped, outcomeEntry{ID: c.ID(), Reason: reasonNoState, Detail: "no " + strings.Join(want, " or ") + " state"})
				}
			}
			// emit writes the -json output: the bare result array, or with
			// -summary the {built, failed, skipped} document.
			emit := func(results []buildResult) error {
				if !summary {
					return g.emitJSON(results)
				}
				sum := buildSummary{Built: []buildResult{}, Failed: []buildResult{}, Skipped: skipped}
				for _, r := range results {
					if r.Error != "" {
						sum.Failed = append(sum.Failed, r)
					} else {
						sum.Built = append(sum.Built, r)
					}
				}
				return g.emitJSON(sum)
			}
			if len(jobsList) == 0 {
				if g.JSON && (summary || len(loadFailed) > 0) {
					if err := emit(append([]buildResult{}, loadFailed...)); err != nil {
						return err
					}
				}
				if len(loadFailed) > 0 {
					return fmt.Errorf("%d template(s) failed to load; nothing to build", len(loadFailed))
				}
				return fmt.Errorf("nothing to build")
			}
			eng, err := g.Engine(ctx)
			if err != nil {
				return err
			}
			host, err := eng.Info(ctx)
			if err != nil {
				return err
			}
			b := builder.New(eng)
			// Preflight each job's target: skip unsupported hosts, emulate
			// cross-arch. The emulation platform is per job: one target needing
			// linux/arm64 must not drag the rest of the batch along. An explicit
			// -platform applies to every job (Options.Platform) instead.
			emulated := map[string]bool{}
			var kept []builder.Job
			for _, j := range jobsList {
				if j.Contract.Requires.Empty() {
					kept = append(kept, j)
					continue
				}
				d := runner.Preflight(j.Contract.Requires, host)
				if d.Skip() && !ignoreRequires {
					g.errorf("skip %s [%s]: %s\n", j.Contract.ID(), j.State, d.Reason)
					skipped = append(skipped, outcomeEntry{ID: j.Contract.ID(), State: j.State, Reason: reasonRequires, Detail: d.Reason})
					continue
				}
				if d.Action == runner.ActionEmulated && platform == "" {
					j.Platform = d.Platform
					if !emulated[j.Contract.ID()] {
						emulated[j.Contract.ID()] = true
						g.printf("building %s under emulation for %s (host is %s/%s)\n", j.Contract.ID(), d.Platform, host.OS, host.Arch)
					}
				}
				kept = append(kept, j)
			}
			jobsList = kept
			if len(jobsList) == 0 {
				if g.JSON && (summary || len(loadFailed) > 0) {
					if err := emit(append([]buildResult{}, loadFailed...)); err != nil {
						return err
					}
				}
				if len(loadFailed) > 0 {
					return fmt.Errorf("%d template(s) failed to load; nothing else to build (all targets skipped by host requirements; -ignore-requires to override)", len(loadFailed))
				}
				return fmt.Errorf("nothing to build (all targets skipped by host requirements; -ignore-requires to override)")
			}
			g.printf("building %d image(s) with %d worker(s)...\n", len(jobsList), jobs)
			started := time.Now()
			// Progress is printed as each job finishes; the results are built
			// from ResolveAll's outcomes afterwards, so a job an interrupt
			// stopped before it started is counted too (it never reaches onDone).
			ran := map[builder.Job]bool{}
			outcomes := b.ResolveAll(ctx, jobsList, jobs, builder.Options{Pull: !noPull, NoCache: noCache, Force: force, Platform: platform},
				func(o builder.Outcome) {
					ran[o.Job] = true
					id := o.Job.Contract.ID()
					if o.Err != nil {
						g.errorf("✗ %s [%s]: %v\n", id, o.Job.State, o.Err)
						if !showLog {
							g.errorf("%s", indent(lastLines(o.Log, 20), "    "))
						}
					} else {
						verb := "reused"
						switch {
						case o.Resolved.Built:
							verb = "built"
						case o.Resolved.Pulled:
							verb = "pulled"
						}
						g.printf("✔ %s [%s] %s (%s) %s  %s\n", id, o.Job.State, verb, o.Resolved.BuildKind, o.Resolved.Elapsed.Round(100*time.Millisecond), o.Resolved.Ref)
					}
					if showLog && o.Log != "" {
						g.printf("%s", indent(o.Log, "    "))
					}
				})
			results := make([]buildResult, 0, len(outcomes)+len(loadFailed))
			results = append(results, loadFailed...)
			var cancelled []buildResult
			for _, o := range outcomes {
				r := buildResult{ID: o.Job.Contract.ID(), State: o.Job.State}
				switch {
				case !ran[o.Job]:
					r.Error = "cancelled before it started"
					cancelled = append(cancelled, r)
					skipped = append(skipped, outcomeEntry{ID: r.ID, State: r.State, Reason: reasonCancelled, Detail: r.Error})
					continue
				case o.Err != nil:
					r.Error = o.Err.Error()
				default:
					r.Ref, r.BuildKind, r.Built, r.Pulled = o.Resolved.Ref, o.Resolved.BuildKind, o.Resolved.Built, o.Resolved.Pulled
					r.Elapsed = o.Resolved.Elapsed.Round(100 * time.Millisecond).String()
				}
				results = append(results, r)
			}
			if push {
				for i := range results {
					r := &results[i]
					if r.Error != "" {
						continue
					}
					if ctx.Err() != nil {
						break // interrupted: push nothing more
					}
					c := findContract(cs, r.ID)
					pushed, err := b.Publish(ctx, c, r.State, registry, nil)
					r.Pushed = pushed
					if err != nil {
						r.Error = err.Error()
						g.errorf("✗ push %s [%s]: %v\n", r.ID, r.State, err)
						continue
					}
					g.printf("⇧ %s [%s] pushed %s\n", r.ID, r.State, strings.Join(pushed, ", "))
				}
			}
			failed := 0
			for _, r := range results {
				if r.Error != "" {
					failed++
				}
			}
			if !summary {
				// The bare array lists every job, a cancelled one with its error.
				results = append(results, cancelled...)
			}
			sort.Slice(results, func(i, j int) bool {
				if results[i].ID != results[j].ID {
					return results[i].ID < results[j].ID
				}
				return results[i].State < results[j].State
			})
			sortOutcomes(skipped)
			if g.JSON {
				if err := emit(results); err != nil {
					return err
				}
			} else {
				ok := len(results) - failed - len(cancelled)
				line := fmt.Sprintf("\n%d ok, %d failed", ok, failed)
				if len(cancelled) > 0 {
					line += fmt.Sprintf(", %d cancelled before starting", len(cancelled))
				}
				g.printf("%s in %s\n", line, time.Since(started).Round(time.Second))
			}
			switch {
			case len(cancelled) > 0 || ctx.Err() != nil:
				return fmt.Errorf("%w: %d build(s) failed, %d cancelled before starting", errInterrupted, failed, len(cancelled))
			case failed > 0:
				return fmt.Errorf("%d build(s) failed", failed)
			}
			return nil
		},
	}
}

// sortOutcomes orders skipped/failed entries by id, then state.
func sortOutcomes(es []outcomeEntry) {
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].ID != es[j].ID {
			return es[i].ID < es[j].ID
		}
		return es[i].State < es[j].State
	})
}

// loadErrID names the template behind a load error: its id when the file can
// be peeked, else its path.
func loadErrID(err error) string {
	var le *loader.Error
	if errors.As(err, &le) {
		if id := loader.PeekID(le.Path); id != "" {
			return id
		}
		return le.Path
	}
	return ""
}

func defaultJobs() int {
	n := runtime.NumCPU()
	if n > 4 {
		n = 4
	}
	if n < 1 {
		n = 1
	}
	return n
}

func findContract(cs []*contract.Contract, id string) *contract.Contract {
	for _, c := range cs {
		if c.ID() == id {
			return c
		}
	}
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n"
}

func indent(s, prefix string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}

// -- images -------------------------------------------------------------------

func cmdImages() *Command {
	var rm bool
	return &Command{
		Name:  "images",
		Short: "list (or remove) the images vulnsuite has built locally",
		Usage: "[-rm]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&rm, "rm", false, "remove every vulnsuite-built image")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			eng, err := g.Engine(ctx)
			if err != nil {
				return err
			}
			refs, err := eng.ImageList(ctx, contract.ImageRepoPrefix+"/")
			if err != nil {
				return err
			}
			sort.Strings(refs)
			if refs == nil {
				refs = []string{} // -json prints [] (not null) when there are none
			}
			if rm {
				type rmFailure struct {
					Ref   string `json:"ref"`
					Error string `json:"error"`
				}
				removed, failed := []string{}, []rmFailure{}
				for _, r := range refs {
					if err := eng.ImageRemove(ctx, r, true); err != nil {
						g.errorf("could not remove %s: %v\n", r, err)
						failed = append(failed, rmFailure{r, err.Error()})
						continue
					}
					removed = append(removed, r)
					g.printf("removed %s\n", r)
				}
				if g.JSON {
					if err := g.emitJSON(map[string]any{"removed": removed, "failed": failed}); err != nil {
						return err
					}
				}
				if len(failed) > 0 {
					return fmt.Errorf("%d of %d image(s) could not be removed", len(failed), len(refs))
				}
				return nil
			}
			if g.JSON {
				return g.emitJSON(refs)
			}
			if len(refs) == 0 {
				g.printf("no vulnsuite images. build some with:  vulnsuite build -t <selector>\n")
				return nil
			}
			tw := tabwriter.NewWriter(g.Stdout, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTATE\tHASH\tREF")
			for _, r := range refs {
				repo, tag, _ := strings.Cut(strings.TrimPrefix(r, contract.ImageRepoPrefix+"/"), ":")
				state, hash, _ := strings.Cut(tag, "-")
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", repo, state, hash, r)
			}
			tw.Flush()
			return nil
		},
	}
}
