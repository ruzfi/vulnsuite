package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/loader"
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
			if err := checkScannerDir("-nuclei-templates", nucleiDir); err != nil {
				return err
			}
			store, err := g.Store()
			if err != nil {
				return err
			}
			// A selector that names a multi-member group prints the family
			// (primary + variants) rather than a single target's detail.
			if members, ok, gerr := store.GroupMembers(args[0]); gerr == nil && ok && len(members) > 1 {
				return printFamily(g, store, args[0], members)
			}
			c, err := store.LoadSelector(args[0])
			if err != nil {
				return err
			}
			var idx *scanners.Index
			if dir := scanners.ResolveDir(nucleiDir); dir != "" {
				if idx, err = loadNucleiIndex(dir); err != nil {
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
			kv("class", strings.Join(m.Class, ", "))
			kv("fidelity", c.Fidelity())
			kv("vuln refs", strings.Join(m.VulnRefs, ", "))
			kv("disclosed", m.Disclosed)
			kv("cwe", strings.Join(m.CWE, ", "))
			kv("tags", strings.Join(m.Tags, ", "))
			kv("maintainer", m.Maintainer)
			kv("added", m.Added)
			kv("updated", c.Updated())
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
				kv("requires", requiresText(c.Requires))
			}
			if reason := runner.HostAccessReason(c); reason != "" {
				kv("host access", reason+" -- run needs -allow-host-access (trust the template first)")
			}
			fmt.Fprintln(g.Stdout)
			for _, name := range c.DeclaredStates() {
				st := c.States[name]
				fmt.Fprintf(g.Stdout, "  %-11s %s -> %s\n", name, c.BuildKind(name), c.ImageRef(name))
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

// familyMember is one row of an `info <group>` family listing.
type familyMember struct {
	ID       string   `json:"id"`
	Variant  string   `json:"variant,omitempty"`
	Primary  bool     `json:"primary"`
	Severity string   `json:"severity,omitempty"`
	Class    []string `json:"class,omitempty"`
	VulnRefs []string `json:"vuln_refs,omitempty"`
	Summary  string   `json:"summary"`
}

// printFamily renders a variant group: the primary first, then each variant,
// with the discriminator that selects it individually.
func printFamily(g *Global, store *loader.Store, handle string, members []loader.GroupMember) error {
	type familyOut struct {
		Group   string         `json:"group"`
		Primary string         `json:"primary,omitempty"`
		Members []familyMember `json:"members"`
	}
	out := familyOut{Group: handle}
	for _, m := range members {
		c, err := store.Load(m.Path)
		if err != nil {
			out.Members = append(out.Members, familyMember{ID: m.ID, Variant: m.Variant, Primary: m.Primary, Summary: "(unloadable: " + err.Error() + ")"})
			continue
		}
		if m.Primary {
			out.Primary = c.ID()
		}
		out.Members = append(out.Members, familyMember{
			ID: c.ID(), Variant: c.Variant(), Primary: m.Primary,
			Severity: c.Metadata.Severity, Class: c.Classes(),
			VulnRefs: c.Metadata.VulnRefs, Summary: c.Metadata.Summary,
		})
	}
	if g.JSON {
		return g.emitJSON(out)
	}
	fmt.Fprintf(g.Stdout, "%s  (variant group, %d members)\n", handle, len(members))
	fmt.Fprintf(g.Stdout, "  `-t %s` runs the primary; `-t %s -variants` runs every member.\n\n", handle, handle)
	tw := tabwriter.NewWriter(g.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  VARIANT\tID\tSEV\tREFS\tSUMMARY")
	for _, m := range out.Members {
		label := m.Variant
		if m.Primary {
			if label == "" {
				label = "primary"
			} else {
				label += " (primary)"
			}
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", dash(label), m.ID, dash(m.Severity), dash(strings.Join(m.VulnRefs, ",")), m.Summary)
	}
	tw.Flush()
	fmt.Fprintf(g.Stdout, "\nInspect one with:  vulnsuite info <id>\n")
	return nil
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
	case "sequence":
		s := p.Sequence
		kinds := make([]string, 0, len(s.Steps))
		for _, st := range s.Steps {
			kinds = append(kinds, st.Kind())
		}
		return fmt.Sprintf("sequence x%d (min_hits %d): %s", s.AttemptCount(), s.MinHitCount(), strings.Join(kinds, ", "))
	}
	return p.Kind()
}

// loadNucleiIndex indexes a nuclei-templates checkout, reusing the index
// cached under the user cache dir (vulnsuite/nuclei-index-*.json) while the
// checkout's template files are unchanged.
func loadNucleiIndex(dir string) (*scanners.Index, error) {
	cache := ""
	if base, err := os.UserCacheDir(); err == nil {
		cache = filepath.Join(base, "vulnsuite")
	}
	return scanners.LoadCached(dir, cache)
}

// checkScannerDir makes an explicit scanner directory flag that is not a
// directory a usage error. Without it a typo silently fell back to
// $NUCLEI_TEMPLATES / ~/nuclei-templates (or $NMAPDIR / the system scripts).
func checkScannerDir(flagName, dir string) error {
	if dir == "" {
		return nil
	}
	st, err := os.Stat(dir)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return usageError{fmt.Sprintf("%s %s: %v", flagName, dir, err)}
	}
	if !st.IsDir() {
		return usageError{fmt.Sprintf("%s %s: not a directory", flagName, dir)}
	}
	return nil
}

// requiresText is a requires block on one line, for info and list's REQUIRES
// column, e.g. "arch amd64, cpu_flags avx512f,bmi2".
func requiresText(r contract.Requires) string {
	var parts []string
	if len(r.HostOS) > 0 {
		parts = append(parts, "host_os "+strings.Join(r.HostOS, "/"))
	}
	if len(r.Arch) > 0 {
		parts = append(parts, "arch "+strings.Join(r.Arch, "/"))
	}
	if r.KVM {
		parts = append(parts, "kvm")
	}
	if r.Emulation != nil && !*r.Emulation { // cpu_flags imply it: not repeated
		parts = append(parts, "no-emulation")
	}
	if len(r.CPUFlags) > 0 {
		parts = append(parts, "cpu_flags "+strings.Join(r.CPUFlags, ","))
	}
	if r.Probe != nil {
		parts = append(parts, fmt.Sprintf("probe (%s)", r.Probe.Reason))
	}
	return strings.Join(parts, ", ")
}
