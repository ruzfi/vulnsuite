package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/loader"
	"github.com/ruzfi/vulnsuite/pkg/runner"
	"github.com/ruzfi/vulnsuite/pkg/scanners"
	"github.com/ruzfi/vulnsuite/pkg/templates"
	"github.com/ruzfi/vulnsuite/pkg/validator"
)

// gather resolves -t selectors / -all into loaded contracts (plus load errors).
func gather(store *loader.Store, selectors []string, all bool) ([]*contract.Contract, []error, error) {
	if !all && len(selectors) == 0 {
		return nil, nil, usageError{"pass -t <template> (repeatable) or -all"}
	}
	paths, err := store.FindMany(selectors, all)
	if err != nil {
		return nil, nil, err
	}
	cs, errs := store.LoadMany(paths)
	return cs, errs, nil
}

// -- list ---------------------------------------------------------------------

type listRow struct {
	ID         string   `json:"id"`
	Severity   string   `json:"severity"`
	States     []string `json:"states"`
	BuildKind  string   `json:"build_kind"`
	Fidelity   string   `json:"fidelity"`
	VulnRefs   []string `json:"vuln_refs"`
	Detection  string   `json:"detection,omitempty"`
	DetectedBy []string `json:"detected_by,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	HostAccess bool     `json:"host_access,omitempty"`
	Summary    string   `json:"summary"`
	Path       string   `json:"path"`
	Error      string   `json:"error,omitempty"`
}

func cmdList() *Command {
	var tag, fidelity, arch string
	return &Command{
		Name: "list", Aliases: []string{"ls"},
		Short: "list templates (with state availability)",
		Usage: "[selector...] [-tag TAG]",
		Long: `A selector is a folder, a contract file, or a template id (substring match
when unique). With no selector every template is listed.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&tag, "tag", "", "only templates carrying this tag")
			fs.StringVar(&fidelity, "fidelity", "", "only templates of this fidelity (real or simulated)")
			fs.StringVar(&arch, "arch", "", "only templates that run on this host arch (e.g. amd64, arm64), honouring requires")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			store, err := g.Store()
			if err != nil {
				return err
			}
			var paths []string
			if len(args) == 0 {
				paths, err = store.All()
			} else {
				paths, err = store.FindMany(args, false)
			}
			if err != nil {
				return err
			}
			var rows []listRow
			for _, p := range paths {
				c, err := store.Load(p)
				if err != nil {
					rows = append(rows, listRow{ID: loader.PeekID(p), Path: p, Error: err.Error()})
					continue
				}
				if tag != "" && !has(c.Metadata.Tags, tag) {
					continue
				}
				if fidelity != "" && c.Fidelity() != fidelity {
					continue
				}
				if arch != "" {
					// a target runs on <arch> if it has no arch requirement, lists
					// it, or can emulate it on linux
					req := c.Requires
					ok := len(req.Arch) == 0 || has(req.Arch, arch) || (req.EmulationAllowed() && !req.KVM)
					if !ok {
						continue
					}
				}
				rows = append(rows, listRow{
					ID: c.ID(), Severity: c.Metadata.Severity, States: c.DeclaredStates(),
					BuildKind: c.BuildKind(contract.StateVulnerable), Fidelity: c.Fidelity(), VulnRefs: c.Metadata.VulnRefs,
					Detection: c.Metadata.Detection, DetectedBy: c.Metadata.DetectedBy, Tags: c.Metadata.Tags,
					HostAccess: runner.HostAccessReason(c) != "",
					Summary:    c.Metadata.Summary, Path: p,
				})
			}
			if g.JSON {
				return g.emitJSON(rows)
			}
			if len(rows) == 0 {
				g.printf("no templates found in %s\n", store.Root)
				return nil
			}
			tw := tabwriter.NewWriter(g.Stdout, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSEV\tFIDELITY\tKIND\tREFS\tDETECTED BY")
			for _, r := range rows {
				if r.Error != "" {
					fmt.Fprintf(tw, "%s\t-\t-\t-\t-\t(unloadable: %s)\n", r.ID, r.Error)
					continue
				}
				det := strings.Join(r.DetectedBy, ",")
				switch {
				case det != "" && r.Detection == "scanner":
					det += " (verified)"
				case det == "" && r.Detection == "custom-only":
					det = "custom-only"
				case det == "":
					det = "- (none linked)"
				}
				kind := r.BuildKind
				if r.HostAccess {
					kind += "*"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Fidelity, kind, strings.Join(r.VulnRefs, ","), det)
			}
			tw.Flush()
			g.printf("\n%d templates in %s\n", len(rows), store.Root)
			if anyHostAccess(rows) {
				g.printf("* needs host access (device/elevated capability); run with -allow-host-access, and only for templates you trust.\n")
			}
			return nil
		},
	}
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// -- validate -----------------------------------------------------------------

func cmdValidate() *Command {
	var sel multiFlag
	var all, strict, allowUnpinned bool
	var nucleiDir string
	var nmapDir string
	return &Command{
		Name:  "validate",
		Short: "validate template contracts (structure + semantic lint)",
		Usage: "[-t SELECTOR]... [-all] [-strict] [-allow-unpinned]",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&sel, "t", "template selector (repeatable); default: every template")
			fs.BoolVar(&all, "all", false, "validate every template (the default when no -t is given)")
			fs.BoolVar(&strict, "strict", false, "treat warnings as errors")
			fs.BoolVar(&allowUnpinned, "allow-unpinned", false, "an unpinned base is a warning, not an error")
			fs.StringVar(&nucleiDir, "nuclei-templates", "", "nuclei-templates checkout to cross-check detected_by against (default: $NUCLEI_TEMPLATES or ~/nuclei-templates when present)")
			fs.StringVar(&nmapDir, "nmap-scripts", "", "nmap NSE scripts dir to cross-check nmap: detected_by refs against (default: $NMAPDIR or the system nmap scripts dir)")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			store, err := g.Store()
			if err != nil {
				return err
			}
			sel = append(sel, args...)
			if len(sel) == 0 {
				all = true
			}
			cs, loadErrs, err := gather(store, sel, all)
			if err != nil {
				return err
			}
			v := &validator.Validator{AllowUnpinned: allowUnpinned}
			if dir := scanners.ResolveDir(nucleiDir); dir != "" {
				idx, err := scanners.Load(dir)
				if err != nil {
					return err
				}
				v.Scanners = idx
				g.printf("cross-checking detected_by against %d nuclei templates from your checkout at %s\n", idx.Count, dir)
			} else {
				g.printf("skipping detected_by cross-check: no nuclei-templates checkout found (set -nuclei-templates, $NUCLEI_TEMPLATES, or clone to ~/nuclei-templates)\n")
			}
			if dir := scanners.ResolveNmapDir(nmapDir); dir != "" {
				idx, err := scanners.LoadNmap(dir)
				if err != nil {
					return err
				}
				v.Nmap = idx
				g.printf("cross-checking detected_by against %d nmap NSE scripts from your checkout at %s\n", idx.Count, dir)
			}
			findings := v.CheckAll(cs)
			nerr, nwarn := validator.Count(findings)
			nerr += len(loadErrs)
			if g.JSON {
				type out struct {
					Templates int                 `json:"templates"`
					Errors    int                 `json:"errors"`
					Warnings  int                 `json:"warnings"`
					LoadErrs  []string            `json:"load_errors,omitempty"`
					Findings  []validator.Finding `json:"findings"`
				}
				o := out{Templates: len(cs), Errors: nerr, Warnings: nwarn, Findings: findings}
				for _, e := range loadErrs {
					o.LoadErrs = append(o.LoadErrs, e.Error())
				}
				if err := g.emitJSON(o); err != nil {
					return err
				}
			} else {
				for _, e := range loadErrs {
					fmt.Fprintf(g.Stdout, "ERROR %v\n", e)
				}
				for _, f := range findings {
					fmt.Fprintln(g.Stdout, f)
				}
				g.printf("\n%d templates, %d errors, %d warnings\n", len(cs), nerr, nwarn)
			}
			if nerr > 0 || (strict && nwarn > 0) {
				return fmt.Errorf("validation failed")
			}
			return nil
		},
	}
}

// -- update-templates -----------------------------------------------------------

func cmdUpdateTemplates() *Command {
	var repo, ref string
	return &Command{
		Name: "update-templates", Aliases: []string{"ut"},
		Short: "download or update the community templates (~/vulnsuite-templates)",
		Usage: "[-repo OWNER/NAME] [-ref BRANCH|TAG]",
		Long: `Fetches ` + templates.DefaultRepo + ` into the templates directory. A git
checkout is pulled (fast-forward only); anything else is replaced by the GitHub
archive of the branch or tag.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&repo, "repo", templates.DefaultRepo, "GitHub repository")
			fs.StringVar(&ref, "ref", templates.DefaultBranch, "branch or tag")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			dir := g.TemplatesDir
			if dir == "" {
				dir = templates.DefaultDir()
			}
			dir, version, err := templates.Update(ctx, templates.UpdateOptions{Dir: dir, Repo: repo, Ref: ref, Output: g.Stdout})
			if err != nil {
				return err
			}
			if g.JSON {
				return g.emitJSON(map[string]string{"dir": dir, "version": version})
			}
			g.printf("templates updated: %s (%s)\n", dir, version)
			return nil
		},
	}
}

// -- version ------------------------------------------------------------------

func cmdVersion() *Command {
	return &Command{
		Name: "version", Short: "print version information", Usage: "",
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			dir, _ := templates.Resolve(g.TemplatesDir)
			if g.JSON {
				return g.emitJSON(map[string]string{"version": Version, "commit": Commit, "date": Date,
					"templates_dir": dir, "templates_version": templates.Version(dir)})
			}
			fmt.Fprintln(g.Stdout, versionString())
			fmt.Fprintf(g.Stdout, "templates: %s", dir)
			if v := templates.Version(dir); v != "" {
				fmt.Fprintf(g.Stdout, " (%s)", v)
			}
			fmt.Fprintln(g.Stdout)
			return nil
		},
	}
}

func anyHostAccess(rows []listRow) bool {
	for _, r := range rows {
		if r.HostAccess {
			return true
		}
	}
	return false
}
