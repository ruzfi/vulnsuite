package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/runner"
	"github.com/ruzfi/vulnsuite/pkg/scanners"
)

// DefaultMaxConcurrent caps simultaneously running targets.
const DefaultMaxConcurrent = 10

func addExposureFlags(fs *flag.FlagSet, exp *runner.Exposure) {
	fs.StringVar(&exp.Mode, "expose", runner.ModeInternal, "exposure mode: internal, host or macvlan")
	fs.StringVar(&exp.Network, "network", runner.DefaultNetwork, "internal network name")
	fs.BoolVar(&exp.Internal, "no-egress", false, "create the internal network with no route off the host")
	fs.StringVar(&exp.Bind, "bind", "127.0.0.1", "host bind address (host mode)")
	fs.IntVar(&exp.HostPort, "host-port", 0, "host port (host mode, single target; default: a free port)")
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

func cmdRun() *Command {
	var sel multiFlag
	var all, detach, noVerify, noPull, noCache, force bool
	var maxConcurrent int
	var targetsFile, platform, readyTimeout, nucleiDir string
	var ignoreRequires bool
	exp := runner.DefaultExposure()
	return &Command{
		Name:  "run",
		Short: "build if needed, then run target(s) in a state and verify them",
		Usage: "[vulnerable|patched] -t SELECTOR... | -all [-expose MODE] [-detach] [-targets-file FILE]",
		Long: `Stands targets up (default state: vulnerable), waits until they are ready,
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
			fs.Var(&sel, "t", "template selector: folder, file or id (repeatable)")
			fs.BoolVar(&all, "all", false, "run every template")
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
			fs.BoolVar(&ignoreRequires, "ignore-requires", false, "run even when the host does not meet a target's requires (arch/kvm/host_os)")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			state := contract.StateVulnerable
			if len(args) > 0 && has(contract.StateNames, args[0]) {
				state = args[0]
				args = args[1:]
			}
			sel = append(sel, args...)
			store, err := g.Store()
			if err != nil {
				return err
			}
			cs, loadErrs, err := gather(store, sel, all)
			if err != nil {
				return err
			}
			if len(loadErrs) > 0 {
				for _, e := range loadErrs {
					g.errorf("ERROR %v\n", e)
				}
				return fmt.Errorf("%d template(s) failed to load", len(loadErrs))
			}
			var runnable []*contract.Contract
			for _, c := range cs {
				if c.HasState(state) {
					runnable = append(runnable, c)
				} else {
					g.printf("skip %s: no %q state\n", c.ID(), state)
				}
			}
			if len(runnable) == 0 {
				return fmt.Errorf("no templates have a %q state", state)
			}
			multi := len(runnable) > 1
			if multi && exp.Mode == runner.ModeMacvlan && exp.IP != "" {
				return usageError{"-ip pins one address; run one template at a time in macvlan mode, or omit -ip"}
			}
			if multi {
				exp.HostPort = 0
			}
			eng, err := g.Engine(ctx)
			if err != nil {
				return err
			}
			r := runner.New(eng)

			// Concurrency cap: containers this batch replaces (same name) are not net new.
			batch := map[string]bool{}
			for _, c := range runnable {
				batch[c.ContainerName(state)] = true
			}
			already, _ := r.Running(ctx, exp.Network)
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
				if free == 0 {
					return fmt.Errorf("max concurrent (%d) already reached: %d target(s) running. bring some down first:  vulnsuite stop", maxConcurrent, netNew)
				}
				overCap, runnable = runnable[free:], runnable[:free]
				g.printf("max concurrent is %d (%d already running): starting %d, skipping %d.\n", maxConcurrent, netNew, len(runnable), len(overCap))
				g.printf("  raise it with -max-concurrent, or run the rest after `vulnsuite stop`.\n\n")
				multi = len(runnable) > 1
			}

			opts := runner.Options{Verify: !noVerify, Build: builder.Options{Pull: !noPull, NoCache: noCache, Force: force, Platform: platform}}
			if readyTimeout != "" {
				d, err := contract.ParseDuration(readyTimeout, 0)
				if err != nil {
					return usageError{err.Error()}
				}
				opts.ReadyTimeout = d
			}
			if !g.JSON && !g.Quiet {
				opts.Build.Output = g.Stdout
			}
			host, herr := eng.Info(ctx)
			if herr != nil {
				return herr
			}
			var idx *scanners.Index
			if dir := scanners.ResolveDir(nucleiDir); dir != "" {
				idx, _ = scanners.Load(dir)
			}
			var handles []*runner.Handle
			var failures, skippedReq []string
			for _, c := range runnable {
				if multi {
					g.printf("\n=== [%s] %s ===\n", c.ID(), state)
				} else {
					g.printf("[%s] %s: %s\n", c.ID(), state, c.Metadata.Summary)
				}
				tgtOpts := opts
				if !c.Requires.Empty() {
					d := runner.Preflight(c.Requires, host)
					switch {
					case d.Skip() && !ignoreRequires:
						g.printf("  skip %s: %s\n", c.ID(), d.Reason)
						skippedReq = append(skippedReq, c.ID())
						continue
					case d.Skip() && ignoreRequires:
						g.printf("  %s does not meet requires (%s) -- running anyway (-ignore-requires)\n", c.ID(), d.Reason)
					case d.Action == runner.ActionEmulated:
						g.printf("  %s: %s\n", c.ID(), d.Reason)
						if tgtOpts.Build.Platform == "" {
							tgtOpts.Build.Platform = d.Platform
						}
					}
				}
				g.printf("resolving image (%s)...\n", c.BuildKind(state))
				h, err := r.Run(ctx, c, state, exp, tgtOpts)
				if err != nil {
					g.errorf("  could not run %s: %v\n", c.ID(), err)
					failures = append(failures, c.ID())
					continue
				}
				handles = append(handles, h)
				verb := "reused"
				switch {
				case h.Image.Built:
					verb = "built"
				case h.Image.Pulled:
					verb = "pulled"
				}
				g.printf("  image: %s (%s)\n", h.Image.Ref, verb)
				if !h.Ready {
					g.printf("  ready: NO -- the healthcheck did not pass in time\n")
				}
				reportVerify(g, h, "  ")
				g.printf("  scanner templates:\n")
				for _, line := range scanners.Match(c, idx).Lines(c) {
					g.printf("  %s\n", line)
				}
			}
			if len(handles) == 0 {
				return fmt.Errorf("nothing came up")
			}

			if g.JSON {
				if err := g.emitJSON(handles); err != nil {
					return err
				}
			} else {
				g.printf("\nScan these with your probe:\n")
				for _, h := range handles {
					tag := fmt.Sprintf("%s [%s]", h.ID, h.State)
					extra := ""
					if h.Exposure.Mode == runner.ModeInternal && h.IP != "" {
						extra = fmt.Sprintf("  (ip %s)", h.IP)
					}
					g.printf("  %-52s %s%s\n", tag, h.ScannerTarget(), extra)
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
					lines = append(lines, fmt.Sprintf("%s  # %s %s", scanURL(h), h.ID, h.State))
				}
				if err := os.WriteFile(targetsFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
					return err
				}
				g.printf("\nwrote %s (%d targets)\n", targetsFile, len(lines))
			}
			if len(failures) > 0 {
				g.errorf("\n%d failed to start: %s\n", len(failures), strings.Join(failures, ", "))
			}
			if len(skippedReq) > 0 {
				g.printf("\n%d skipped (host does not meet requires): %s\n", len(skippedReq), strings.Join(skippedReq, ", "))
				g.printf("  override with -ignore-requires, or run on a matching host.\n")
			}
			if len(overCap) > 0 {
				ids := make([]string, 0, len(overCap))
				for _, c := range overCap {
					ids = append(ids, c.ID())
				}
				g.printf("\n%d not started (over the -max-concurrent %d cap): %s\n", len(overCap), maxConcurrent, strings.Join(ids, ", "))
			}
			if !g.JSON {
				g.printf("\nTear down:  vulnsuite stop   (brings down all %d target(s))\n", len(handles))
			}
			if detach {
				if len(failures) > 0 {
					return fmt.Errorf("%d target(s) failed", len(failures))
				}
				return nil
			}
			g.printf("\nHolding. Ctrl-C to tear down this batch.\n")
			sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			<-sigCtx.Done()
			stop()
			g.printf("\ntearing down...\n")
			for _, h := range handles {
				r.Stop(context.Background(), h)
			}
			if len(failures) > 0 {
				return fmt.Errorf("%d target(s) failed", len(failures))
			}
			return nil
		},
	}
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
	var pruneNet bool
	return &Command{
		Name: "stop", Aliases: []string{"down"},
		Short: "tear down running targets (all, or selected templates)",
		Usage: "[-t SELECTOR]... [-prune-net]",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&sel, "t", "only this template/selector (repeatable; default: everything vulnsuite started)")
			fs.StringVar(&network, "network", runner.DefaultNetwork, "internal network name")
			fs.BoolVar(&pruneNet, "prune-net", false, "also remove the internal network when stopping everything")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			sel = append(sel, args...)
			eng, err := g.Engine(ctx)
			if err != nil {
				return err
			}
			r := runner.New(eng)
			var ids []string
			if len(sel) > 0 {
				store, err := g.Store()
				if err != nil {
					return err
				}
				cs, _, err := gather(store, sel, false)
				if err != nil {
					return err
				}
				for _, c := range cs {
					ids = append(ids, c.ID())
				}
			} else {
				ids = []string{""}
			}
			var removed []string
			for _, id := range ids {
				names, err := r.StopAll(ctx, id)
				removed = append(removed, names...)
				if err != nil {
					return err
				}
			}
			if g.JSON {
				return g.emitJSON(map[string]any{"removed": removed})
			}
			if len(removed) == 0 {
				g.printf("nothing to stop\n")
			} else {
				g.printf("stopped %d container(s):\n", len(removed))
				for _, n := range removed {
					g.printf("  %s\n", n)
				}
			}
			if pruneNet && len(sel) == 0 {
				if err := r.PruneNetwork(ctx, network); err == nil {
					g.printf("removed network %s\n", network)
				} else {
					g.errorf("could not remove network %s: %v\n", network, err)
				}
			}
			return nil
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
			fmt.Fprintln(tw, "ID\tSTATE\tIP\tHOST PORT\tSTATUS")
			for _, r := range rows {
				hp := "-"
				if r.HostPort > 0 {
					hp = fmt.Sprint(r.HostPort)
				}
				ip := r.IP
				if ip == "" {
					ip = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.State, ip, hp, r.Status)
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
			fs.StringVar(&by, "by", "ip", "address targets by container ip, network alias, or published host port")
			fs.StringVar(&network, "network", runner.DefaultNetwork, "internal network name")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			store, err := g.Store()
			if err != nil {
				return err
			}
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
			byID, err := store.ByID()
			if err != nil {
				return err
			}
			type pair struct {
				ID    string `json:"id"`
				State string `json:"state"`
				URL   string `json:"url"`
			}
			var pairs []pair
			for _, r := range rows {
				c, ok := byID[r.ID]
				if !ok {
					g.errorf("skip %s: template not found in %s\n", r.ID, store.Root)
					continue
				}
				port := c.Service.PrimaryPort()
				var host string
				p := port.Container
				switch by {
				case "alias":
					host = r.ID
				case "host":
					if r.HostPort == 0 {
						continue
					}
					host, p = "127.0.0.1", r.HostPort
				default:
					host = r.IP
				}
				if host == "" {
					continue
				}
				pairs = append(pairs, pair{r.ID, r.State, runner.FormatTarget(port.Scheme(), host, p)})
			}
			if len(pairs) == 0 {
				return fmt.Errorf("running targets have no resolvable address yet (try again in a moment, or -by alias)")
			}
			if g.JSON {
				return g.emitJSON(pairs)
			}
			if file != "" {
				var lines []string
				for _, p := range pairs {
					lines = append(lines, p.URL)
				}
				if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
					return err
				}
				g.printf("wrote %s (%d targets, by %s)\nscan exactly these (no subnet sweep):\n  nuclei -l %s\n", file, len(pairs), by, file)
				return nil
			}
			for _, p := range pairs {
				g.printf("%-48s # %s %s\n", p.URL, p.ID, p.State)
			}
			g.printf("\n%d targets. Scan just these instead of the subnet, e.g.:\n  vulnsuite targets -file targets.txt && nuclei -l targets.txt\n", len(pairs))
			return nil
		},
	}
}
