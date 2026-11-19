package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/ruzfi/vulnsuite/pkg/runner"
)

func cmdHost() *Command {
	var noPull bool
	return &Command{
		Name: "host", Aliases: []string{"doctor"},
		Short: "show what the container daemon's machine offers targets (arch, CPU flags, KVM, kernel, amd64 emulation)",
		Usage: "[-no-pull]",
		Long: `Answers "can this daemon run target X?" before running it. The daemon's API
gives its OS and arch; the rest is read on the daemon's machine (not the one
running vulnsuite: a VM in between can hide CPU flags) in short-lived
containers from a digest-pinned busybox image, with no network and no
capabilities:

  kernel     the daemon's kernel version (uname -r)
  /dev/kvm   whether the kernel has a kvm device (requires.kvm needs it)
  cpu flags  /proc/cpuinfo's flags (x86) or Features (arm64), as requires.cpu_flags names them
  amd64      native on an amd64 daemon; elsewhere whether an amd64 container runs
             (emulated, via qemu or Rosetta) or not (unavailable)

What cannot be read is reported as unknown with the reason (e.g. offline: the
probe image cannot be pulled), and the command exits non-zero.`,
		NoArgs: true,
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&noPull, "no-pull", false, "never pull the probe image; what needs it is reported unknown")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			eng, err := g.Engine(ctx)
			if err != nil {
				return err
			}
			rep, err := runner.Host(ctx, eng, runner.HostProbeOptions{NoPull: noPull, Progress: g.progress()})
			if rep == nil {
				return err
			}
			if g.JSON {
				if jerr := g.emitJSON(rep); jerr != nil {
					return jerr
				}
			} else {
				printHostReport(g, rep)
			}
			if err != nil {
				return err
			}
			var unknown []string
			if rep.ProbeError != "" {
				unknown = append(unknown, "kernel, /dev/kvm and CPU flags")
			}
			if rep.AMD64 == runner.AMD64Unknown {
				unknown = append(unknown, "amd64 emulation")
			}
			if len(unknown) > 0 {
				return errors.New("could not read " + strings.Join(unknown, " or ") + " (see above)")
			}
			return nil
		},
	}
}

func printHostReport(g *Global, rep *runner.HostReport) {
	tw := tabwriter.NewWriter(g.Stdout, 2, 4, 2, ' ', 0)
	unknown := "unknown (" + rep.ProbeError + ")"
	row := func(k, v string) { fmt.Fprintf(tw, "%s\t%s\n", k, v) }
	row("daemon", rep.OS+"/"+rep.Arch)
	row("engine", rep.Engine)
	if rep.ProbeError != "" {
		row("kernel", unknown)
		row("/dev/kvm", unknown)
		row("cpu flags", unknown)
	} else {
		row("kernel", rep.Kernel)
		kvm := "no"
		if rep.KVM != nil && *rep.KVM {
			kvm = "yes"
		}
		row("/dev/kvm", kvm)
		row("cpu flags", fmt.Sprintf("%s (%d)", strings.Join(rep.CPUFlags, " "), len(rep.CPUFlags)))
	}
	amd := rep.AMD64
	if rep.AMD64Detail != "" {
		amd += " (" + rep.AMD64Detail + ")"
	}
	row("amd64", amd)
	row("probe image", rep.ProbeImage)
	tw.Flush()
}
