package cli

import (
	"context"
	"flag"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
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
	var sel multiFlag
	var all, noCache, force, noPull, push, showLog, ignoreRequires bool
	var states, registry, platform string
	var jobs int
	return &Command{
		Name:  "build",
		Short: "build (or pull) the images for templates, content-addressed, in parallel",
		Usage: "-t SELECTOR... | -all [-state vulnerable|patched|all] [-j N] [-push -registry REG]",
		Long: `Every state's image is tagged ` + contract.ImageRepoPrefix + `/<id>:<state>-<hash> where the hash
covers the base, patches, overlays and environment. Identical inputs are never
rebuilt. Prebuilt (image-kind) states are pulled, not built.

With -push, each image is also tagged <registry>/<id>:<state> and
<registry>/<id>:<state>-<hash> and pushed. Credentials come from
VULNSUITE_REGISTRY_USER / VULNSUITE_REGISTRY_TOKEN or ~/.docker/config.json.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&sel, "t", "template selector: folder, file or id (repeatable)")
			fs.BoolVar(&all, "all", false, "build every template")
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
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			sel = append(sel, args...)
			want, err := parseStates(states)
			if err != nil {
				return err
			}
			if push && registry == "" {
				return usageError{"-push needs -registry"}
			}
			store, err := g.Store()
			if err != nil {
				return err
			}
			cs, loadErrs, err := gather(store, sel, all)
			if err != nil {
				return err
			}
			for _, e := range loadErrs {
				g.errorf("ERROR %v\n", e)
			}
			var jobsList []builder.Job
			for _, c := range cs {
				for _, s := range want {
					if c.HasState(s) {
						jobsList = append(jobsList, builder.Job{Contract: c, State: s})
					}
				}
			}
			if len(jobsList) == 0 {
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
			// Preflight each job's target: skip unsupported hosts, emulate cross-arch.
			platformFor := map[string]string{}
			var kept []builder.Job
			for _, j := range jobsList {
				if j.Contract.Requires.Empty() {
					kept = append(kept, j)
					continue
				}
				d := runner.Preflight(j.Contract.Requires, host)
				if d.Skip() && !ignoreRequires {
					g.errorf("skip %s [%s]: %s\n", j.Contract.ID(), j.State, d.Reason)
					continue
				}
				if d.Action == runner.ActionEmulated {
					platformFor[j.Contract.ID()] = d.Platform
				}
				kept = append(kept, j)
			}
			jobsList = kept
			if len(jobsList) == 0 {
				return fmt.Errorf("nothing to build (all targets skipped by host requirements; -ignore-requires to override)")
			}
			if platform == "" && len(platformFor) > 0 {
				// emulate: pick the single platform (targets needing emulation on
				// this host all target the same arch).
				for _, pf := range platformFor {
					platform = pf
				}
				g.printf("building under emulation for %s (host is %s/%s)\n", platform, host.OS, host.Arch)
			}
			g.printf("building %d image(s) with %d worker(s)...\n", len(jobsList), jobs)
			started := time.Now()
			results := make([]buildResult, 0, len(jobsList))
			var failed int
			outcomes := b.ResolveAll(ctx, jobsList, jobs, builder.Options{Pull: !noPull, NoCache: noCache, Force: force, Platform: platform},
				func(o builder.Outcome) {
					r := buildResult{ID: o.Job.Contract.ID(), State: o.Job.State}
					if o.Err != nil {
						failed++
						r.Error = o.Err.Error()
						g.errorf("✗ %s [%s]: %v\n", r.ID, r.State, o.Err)
						if !showLog {
							g.errorf("%s", indent(lastLines(o.Log, 20), "    "))
						}
					} else {
						r.Ref, r.BuildKind, r.Built, r.Pulled = o.Resolved.Ref, o.Resolved.BuildKind, o.Resolved.Built, o.Resolved.Pulled
						r.Elapsed = o.Resolved.Elapsed.Round(100 * time.Millisecond).String()
						verb := "reused"
						switch {
						case o.Resolved.Built:
							verb = "built"
						case o.Resolved.Pulled:
							verb = "pulled"
						}
						g.printf("✔ %s [%s] %s (%s) %s  %s\n", r.ID, r.State, verb, r.BuildKind, r.Elapsed, r.Ref)
					}
					if showLog && o.Log != "" {
						g.printf("%s", indent(o.Log, "    "))
					}
					results = append(results, r)
				})
			_ = outcomes
			if push {
				for i := range results {
					r := &results[i]
					if r.Error != "" {
						continue
					}
					c := findContract(cs, r.ID)
					pushed, err := b.Publish(ctx, c, r.State, registry, nil)
					r.Pushed = pushed
					if err != nil {
						failed++
						r.Error = err.Error()
						g.errorf("✗ push %s [%s]: %v\n", r.ID, r.State, err)
						continue
					}
					g.printf("⇧ %s [%s] pushed %s\n", r.ID, r.State, strings.Join(pushed, ", "))
				}
			}
			sort.Slice(results, func(i, j int) bool {
				if results[i].ID != results[j].ID {
					return results[i].ID < results[j].ID
				}
				return results[i].State < results[j].State
			})
			if g.JSON {
				if err := g.emitJSON(results); err != nil {
					return err
				}
			} else {
				g.printf("\n%d ok, %d failed in %s\n", len(results)-failed, failed, time.Since(started).Round(time.Second))
			}
			if failed > 0 {
				return fmt.Errorf("%d build(s) failed", failed)
			}
			return nil
		},
	}
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
			if rm {
				for _, r := range refs {
					if err := eng.ImageRemove(ctx, r, true); err != nil {
						g.errorf("could not remove %s: %v\n", r, err)
						continue
					}
					g.printf("removed %s\n", r)
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
