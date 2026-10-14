package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/runner"
	"github.com/ruzfi/vulnsuite/pkg/scanners"
)

type infoOut struct {
	*contract.Contract
	Scanners scanners.Report `json:"scanners"`
}

func cmdInfo() *Command {
	var nucleiDir string
	return &Command{
		Name: "info", Aliases: []string{"show"},
		Short: "show a template: states, build kinds, probes, and the scanner templates that detect it",
		Usage: "<selector> [-nuclei-templates DIR]",
		Long: `Prints everything a user deploying the target wants to know, including which
scanner templates (nuclei:<id>) should fire on it. With a nuclei-templates
checkout available ($NUCLEI_TEMPLATES, ~/nuclei-templates or -nuclei-templates)
the ids are resolved to files and templates matching the target's CVEs are
suggested. When nothing is linked, that is a detection gap worth closing by
writing a template and contributing it upstream.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&nucleiDir, "nuclei-templates", "", "nuclei-templates checkout")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			if len(args) != 1 {
				return usageError{"pass exactly one selector"}
			}
			store, err := g.Store()
			if err != nil {
				return err
			}
			c, err := store.LoadSelector(args[0])
			if err != nil {
				return err
			}
			var idx *scanners.Index
			if dir := scanners.ResolveDir(nucleiDir); dir != "" {
				if idx, err = scanners.Load(dir); err != nil {
					return err
				}
			}
			rep := scanners.Match(c, idx)
			if g.JSON {
				return g.emitJSON(infoOut{c, rep})
			}
			m := c.Metadata
			fmt.Fprintf(g.Stdout, "%s\n  %s\n\n", c.ID(), m.Summary)
			kv := func(k, v string) {
				if v != "" {
					fmt.Fprintf(g.Stdout, "  %-12s %s\n", k, v)
				}
			}
			kv("severity", m.Severity)
			kv("fidelity", c.Fidelity())
			kv("vuln refs", strings.Join(m.VulnRefs, ", "))
			kv("cwe", strings.Join(m.CWE, ", "))
			kv("tags", strings.Join(m.Tags, ", "))
			kv("maintainer", m.Maintainer)
			kv("added", m.Added)
			kv("template", c.SourcePath)
			base := c.Base.Kind
			switch c.Base.Kind {
			case contract.BaseImage:
				base += " " + c.Base.Image
				if c.Base.Digest == "" {
					base += " (unpinned)"
				}
			case contract.BaseSource:
				base += " " + c.Base.Repo + "@" + c.Base.Commit
			case contract.BaseBuild:
				base += " " + c.Base.Context + "/"
			}
			kv("base", base)
			var ports []string
			for _, p := range c.Service.Ports {
				ports = append(ports, fmt.Sprintf("%d/%s", p.Container, p.Protocol))
			}
			kv("ports", strings.Join(ports, ", "))
			if !c.Requires.Empty() {
				var parts []string
				if len(c.Requires.HostOS) > 0 {
					parts = append(parts, "host_os "+strings.Join(c.Requires.HostOS, "/"))
				}
				if len(c.Requires.Arch) > 0 {
					parts = append(parts, "arch "+strings.Join(c.Requires.Arch, "/"))
				}
				if c.Requires.KVM {
					parts = append(parts, "kvm")
				}
				if !c.Requires.EmulationAllowed() {
					parts = append(parts, "no-emulation")
				}
				kv("requires", strings.Join(parts, ", "))
			}
			if reason := runner.HostAccessReason(c); reason != "" {
				kv("host access", reason+" -- run needs -allow-host-access (trust the template first)")
			}
			fmt.Fprintln(g.Stdout)
			for _, name := range c.DeclaredStates() {
				st := c.States[name]
				fmt.Fprintf(g.Stdout, "  %-11s %s build -> %s\n", name, c.BuildKind(name), c.ImageRef(name))
				for _, p := range st.Verify {
					fmt.Fprintf(g.Stdout, "              verify %s\n", probeSummary(p))
				}
			}
			if len(m.References) > 0 {
				fmt.Fprintln(g.Stdout)
				for _, r := range m.References {
					fmt.Fprintf(g.Stdout, "  ref  %s\n", r)
				}
			}
			fmt.Fprintln(g.Stdout)
			fmt.Fprintln(g.Stdout, "scanner templates:")
			for _, line := range rep.Lines(c) {
				fmt.Fprintln(g.Stdout, line)
			}
			return nil
		},
	}
}

func probeSummary(p contract.Probe) string {
	switch p.Kind() {
	case "http":
		h := p.HTTP
		path := h.RawPath
		if path == "" {
			path = h.Path
		}
		var asserts []string
		if h.Status != nil {
			asserts = append(asserts, fmt.Sprintf("status %d", *h.Status))
		}
		if len(h.StatusIn) > 0 {
			asserts = append(asserts, fmt.Sprintf("status in %v", h.StatusIn))
		}
		if h.BodyMatches != "" {
			asserts = append(asserts, "body ~ /"+h.BodyMatches+"/")
		}
		if h.BodyAbsent != "" {
			asserts = append(asserts, "body !~ /"+h.BodyAbsent+"/")
		}
		for k, v := range h.HeaderMatches {
			asserts = append(asserts, k+" ~ /"+v+"/")
		}
		m := h.Method
		if m == "" {
			m = "GET"
		}
		return fmt.Sprintf("http %s %s -> %s", m, path, strings.Join(asserts, ", "))
	case "tcp":
		return fmt.Sprintf("tcp :%d send %q banner ~ /%s/", p.TCP.Port, p.TCP.Send, p.TCP.BannerMatches)
	case "exec":
		return fmt.Sprintf("exec %q stdout ~ /%s/", p.Exec.Run, p.Exec.StdoutMatches)
	case "net":
		return fmt.Sprintf("net :%d, %d-step dialogue", p.Net.Port, len(p.Net.Steps))
	}
	return p.Kind()
}
