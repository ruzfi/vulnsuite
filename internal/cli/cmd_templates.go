package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/kev"
	"github.com/ruzfi/vulnsuite/pkg/loader"
	"github.com/ruzfi/vulnsuite/pkg/runner"
	"github.com/ruzfi/vulnsuite/pkg/scanners"
	"github.com/ruzfi/vulnsuite/pkg/templates"
	"github.com/ruzfi/vulnsuite/pkg/validator"
)

// gather resolves -t selectors / -all into loaded contracts (plus load errors).
// With variants set, a selector that names a group expands to all its members,
// and -all returns the full matrix; otherwise a group resolves to its primary
// and -all returns one target per family (primaries) plus all ungrouped targets.
func gather(store *loader.Store, selectors []string, all, variants bool) ([]*contract.Contract, []error, error) {
	if !all && len(selectors) == 0 {
		return nil, nil, usageError{"pass -t <template> (repeatable) or -all"}
	}
	paths, err := store.FindMany(selectors, all, variants)
	if err != nil {
		return nil, nil, err
	}
	cs, errs := store.LoadMany(paths)
	return cs, errs, nil
}

// -- list ---------------------------------------------------------------------

type listRow struct {
	ID         string   `json:"id"`
	Group      string   `json:"group,omitempty"`
	Variant    string   `json:"variant,omitempty"`
	Primary    bool     `json:"primary,omitempty"`
	GroupSize  int      `json:"group_size,omitempty"`
	Category   string   `json:"category,omitempty"`
	Severity   string   `json:"severity"`
	Class      []string `json:"class,omitempty"`
	CVE        bool     `json:"cve"`
	KEV        *bool    `json:"kev,omitempty"`
	Year       string   `json:"year,omitempty"`
	Disclosed  string   `json:"disclosed,omitempty"`
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
	var tag, fidelity, arch, category, year, since, groupFilter string
	var class, ref multiFlag
	var onlyKEV, noKEV, cve, noCVE, refreshKEV, variants bool
	return &Command{
		Name: "list", Aliases: []string{"ls", "search"},
		Short: "list and filter templates by class, KEV, product surface, CVE and year",
		Usage: "[selector...] [-group H] [-variants] [-ref ID]... [-class C]... [-kev] [-category P] [-cve] [-year YYYY]",
		Long: `A selector is a folder, a contract file, or a template id (substring match
when unique). A ref-shaped selector (CVE-..., GHSA-..., GO-..., VS-...) that
matches no id/file/folder resolves against vuln_refs instead, so
` + "`search CVE-2026-109619`" + ` just works. With no selector every template is listed.

Filters compose (all must match). Finding class, CVE and KEV status are derived
from contract metadata (taxonomy v2) and shown as columns:

  -ref         a specific vuln_refs id -- CVE-, GHSA-, GO- or VS-... (repeatable;
               match any; case-insensitive). Finds secondary refs that are in no id.
  -class       finding class: vuln, misconfig, exposure, default-login,
               weak-crypto (repeatable; a template matches if it carries any)
  -category    product surface -- the top directory level (web-apps,
               web-servers, databases, network-services, iot, misc). Alias -product.
  -cve/-no-cve has / has no CVE id in vuln_refs (boolean; use -ref for a specific id)
  -kev/-no-kev on / not on the CISA Known Exploited Vulnerabilities catalog
  -year        disclosure year (metadata.disclosed, else the CVE-id year)
  -since       disclosed on or after this ISO date (YYYY-MM-DD)

KEV membership is derived by cross-referencing a target's CVEs against the CISA
KEV catalog. The catalog is read from the templates checkout's data/cisa-kev.txt
(kept fresh upstream); -refresh-kev fetches the live CISA feed and caches it at
` + "`~/.cache/vulnsuite/cisa-kev.json`" + `. Offline with neither present, KEV is
shown as "?" and -kev/-no-kev cannot be used.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&tag, "tag", "", "only templates carrying this tag")
			fs.StringVar(&fidelity, "fidelity", "", "only templates of this fidelity (real or simulated)")
			fs.StringVar(&groupFilter, "group", "", "only members of this variant group (shows the whole family)")
			fs.BoolVar(&variants, "variants", false, "expand variant groups to all members (default: collapse each group to its primary)")
			fs.StringVar(&arch, "arch", "", "only templates that run on this host arch (e.g. amd64, arm64), honouring requires")
			fs.Var(&class, "class", "only templates of this finding class (repeatable; match any): vuln, misconfig, exposure, default-login, weak-crypto")
			fs.StringVar(&category, "category", "", "only templates in this product surface (top directory level), e.g. web-apps")
			fs.StringVar(&category, "product", "", "alias for -category")
			fs.BoolVar(&cve, "cve", false, "only templates with a CVE id in vuln_refs")
			fs.BoolVar(&noCVE, "no-cve", false, "only templates without a CVE id")
			fs.Var(&ref, "ref", "only templates whose vuln_refs contains this id (repeatable; match any; case-insensitive): CVE-, GHSA-, GO-, VS-...")
			fs.BoolVar(&onlyKEV, "kev", false, "only templates on the CISA KEV catalog")
			fs.BoolVar(&noKEV, "no-kev", false, "only templates not on the CISA KEV catalog")
			fs.StringVar(&year, "year", "", "only templates disclosed in this year (YYYY)")
			fs.StringVar(&since, "since", "", "only templates disclosed on or after this ISO date (YYYY-MM-DD)")
			fs.BoolVar(&refreshKEV, "refresh-kev", false, "fetch the live CISA KEV feed and refresh the local cache before filtering")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			if cve && noCVE {
				return usageError{"-cve and -no-cve are mutually exclusive"}
			}
			if onlyKEV && noKEV {
				return usageError{"-kev and -no-kev are mutually exclusive"}
			}
			for _, cl := range class {
				if !has(contract.Classes, cl) {
					return usageError{fmt.Sprintf("unknown -class %q; want one of %s", cl, strings.Join(contract.Classes, ", "))}
				}
			}
			store, err := g.Store()
			if err != nil {
				return err
			}
			// Resolve the KEV set when it is needed: always, to populate the
			// column, and definitively when -kev/-no-kev filters on it.
			kevSet, kevSrc, err := kev.Resolve(ctx, kev.Options{TemplatesDir: store.Root, Refresh: refreshKEV})
			if err != nil {
				return err
			}
			kevKnown := kevSrc.Origin != kev.OriginNone
			if (onlyKEV || noKEV) && !kevKnown {
				return fmt.Errorf("cannot filter by KEV: catalog unavailable (offline and no cache). Run with -refresh-kev, or point -templates at a checkout with data/cisa-kev.txt")
			}
			groupSizes, err := store.Groups()
			if err != nil {
				return err
			}
			expanded := variants || groupFilter != ""
			var paths []string
			switch {
			case groupFilter != "":
				members, ok, gerr := store.GroupMembers(groupFilter)
				if gerr != nil {
					return gerr
				}
				if !ok {
					return fmt.Errorf("no variant group %q (see the GROUP column in `vulnsuite list`)", groupFilter)
				}
				for _, m := range members {
					paths = append(paths, m.Path)
				}
			case len(args) == 0:
				paths, err = store.FindMany(nil, true, variants)
			default:
				paths, err = store.FindMany(args, false, variants)
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
				if category != "" && store.Category(p) != category {
					continue
				}
				if len(class) > 0 && !anyClass(c, class) {
					continue
				}
				if len(ref) > 0 && !anyRef(c, ref) {
					continue
				}
				if cve && !c.IsCVETracked() {
					continue
				}
				if noCVE && c.IsCVETracked() {
					continue
				}
				onKEV := kevSet.Any(c.CVEs())
				if onlyKEV && !onKEV {
					continue
				}
				if noKEV && onKEV {
					continue
				}
				if year != "" && c.Year() != year {
					continue
				}
				if since != "" {
					d := c.DisclosedDate()
					if d == "" || d < since {
						continue
					}
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
				row := listRow{
					ID: c.ID(), Group: c.Group(), Variant: c.Variant(), Primary: c.IsPrimary(),
					GroupSize: len(groupSizes[c.Group()]),
					Category:  store.Category(p), Severity: c.Metadata.Severity,
					Class: c.Classes(), CVE: c.IsCVETracked(), Year: c.Year(), Disclosed: c.Metadata.Disclosed,
					States: c.DeclaredStates(), BuildKind: c.BuildKind(contract.StateVulnerable),
					Fidelity: c.Fidelity(), VulnRefs: c.Metadata.VulnRefs,
					Detection: c.Metadata.Detection, DetectedBy: c.Metadata.DetectedBy, Tags: c.Metadata.Tags,
					HostAccess: runner.HostAccessReason(c) != "",
					Summary:    c.Metadata.Summary, Path: p,
				}
				if kevKnown {
					v := onKEV
					row.KEV = &v
				}
				rows = append(rows, row)
			}
			if g.JSON {
				return g.emitJSON(rows)
			}
			if len(rows) == 0 {
				g.printf("no templates found in %s\n", store.Root)
				return nil
			}
			tw := tabwriter.NewWriter(g.Stdout, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tCATEGORY\tGROUP\tSEV\tCLASS\tCVE\tKEV\tFIDELITY\tKIND\tREFS\tDETECTED BY")
			for _, r := range rows {
				if r.Error != "" {
					fmt.Fprintf(tw, "%s\t-\t-\t-\t-\t-\t-\t-\t-\t-\t(unloadable: %s)\n", r.ID, r.Error)
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
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.ID, dash(r.Category), groupCell(r, expanded), r.Severity, dash(strings.Join(r.Class, ",")),
					yesNo(r.CVE), kevCell(r.KEV), r.Fidelity, kind, strings.Join(r.VulnRefs, ","), det)
			}
			tw.Flush()
			g.printf("\n%d templates in %s\n", len(rows), store.Root)
			g.printf("KEV source: %s\n", kevSrc)
			if anyHostAccess(rows) {
				g.printf("* needs host access (device/elevated capability); run with -allow-host-access, and only for templates you trust.\n")
			}
			return nil
		},
	}
}

// anyClass reports whether c carries any of the requested finding classes.
func anyClass(c *contract.Contract, want []string) bool {
	for _, cl := range want {
		if c.HasClass(cl) {
			return true
		}
	}
	return false
}

// anyRef reports whether c's vuln_refs contains any of the requested ids.
func anyRef(c *contract.Contract, want []string) bool {
	for _, r := range want {
		if c.HasRef(r) {
			return true
		}
	}
	return false
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// groupCell renders the GROUP column. Collapsed, a primary with siblings shows
// "handle (+N)" so the family's size is visible without expanding; expanded,
// each member shows its handle annotated with its variant (or "primary").
func groupCell(r listRow, expanded bool) string {
	if r.Group == "" {
		return "-"
	}
	if expanded {
		switch {
		case r.Primary:
			return r.Group + " (primary)"
		case r.Variant != "":
			return r.Group + " (" + r.Variant + ")"
		default:
			return r.Group
		}
	}
	if r.GroupSize > 1 {
		return fmt.Sprintf("%s (+%d)", r.Group, r.GroupSize-1)
	}
	return r.Group
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "-"
}

// kevCell renders the KEV column: yes/-, or "?" when the catalog is unavailable.
func kevCell(b *bool) string {
	if b == nil {
		return "?"
	}
	return yesNo(*b)
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
			// Always expand groups when validating: the per-group rules
			// (one primary, unique variants) need every member in view.
			cs, loadErrs, err := gather(store, sel, all, true)
			if err != nil {
				return err
			}
			v := &validator.Validator{
				AllowUnpinned: allowUnpinned,
				CategoryOf:    func(c *contract.Contract) string { return store.Category(c.SourcePath) },
			}
			if dir := scanners.ResolveDir(nucleiDir); dir != "" {
				idx, err := scanners.Load(dir)
				if err != nil {
					return err
				}
				v.Scanners = idx
				if !g.JSON {
					g.printf("cross-checking detected_by against %d nuclei templates from your checkout at %s\n", idx.Count, dir)
				}
			} else if !g.JSON {
				g.printf("skipping detected_by cross-check: no nuclei-templates checkout found (set -nuclei-templates, $NUCLEI_TEMPLATES, or clone to ~/nuclei-templates)\n")
			}
			if dir := scanners.ResolveNmapDir(nmapDir); dir != "" {
				idx, err := scanners.LoadNmap(dir)
				if err != nil {
					return err
				}
				v.Nmap = idx
				if !g.JSON {
					g.printf("cross-checking detected_by against %d nmap NSE scripts from your checkout at %s\n", idx.Count, dir)
				}
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
