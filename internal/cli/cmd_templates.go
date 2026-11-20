package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

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

// fallbackID names a template that failed to load: its metadata.id when
// that much can be read, else its folder (or file) name.
func fallbackID(path string) string {
	if id := loader.PeekID(path); id != "" {
		return id
	}
	for _, n := range loader.ContractNames {
		if filepath.Base(path) == n {
			return filepath.Base(filepath.Dir(path))
		}
	}
	return filepath.Base(path)
}

// -- list ---------------------------------------------------------------------

type listRow struct {
	ID        string   `json:"id"`
	Group     string   `json:"group,omitempty"`
	Variant   string   `json:"variant,omitempty"`
	Primary   bool     `json:"primary,omitempty"`
	GroupSize int      `json:"group_size,omitempty"`
	Category  string   `json:"category,omitempty"`
	Severity  string   `json:"severity"`
	Class     []string `json:"class,omitempty"`
	CVE       bool     `json:"cve"`
	KEV       *bool    `json:"kev,omitempty"`
	// KEVSource is where the KEV column came from and how old it is (the same
	// for every row; per row so -json stays a plain array).
	KEVSource *kevSourceInfo `json:"kev_source,omitempty"`
	Year      string         `json:"year,omitempty"`
	Disclosed string         `json:"disclosed,omitempty"`
	States    []string       `json:"states"`
	BuildKind string         `json:"build_kind"`
	Fidelity  string         `json:"fidelity"`
	// Verification is verified or unverified (metadata.verification, with
	// its default), and VerifiedOn the evidence of the last verifying run.
	Verification string               `json:"verification"`
	VerifiedOn   *contract.VerifiedOn `json:"verified_on,omitempty"`
	VulnRefs     []string             `json:"vuln_refs"`
	Detection    string               `json:"detection,omitempty"`
	DetectedBy   []string             `json:"detected_by,omitempty"`
	Tags         []string             `json:"tags,omitempty"`
	HostAccess   bool                 `json:"host_access,omitempty"`
	// Requires is the template's requires block (absent when it has none).
	Requires *contract.Requires `json:"requires,omitempty"`
	Summary  string             `json:"summary"`
	Path     string             `json:"path"`
	Error    string             `json:"error,omitempty"`
}

// kevSourceInfo is the KEV data's provenance and age, for list -json.
type kevSourceInfo struct {
	Origin         string `json:"origin"`
	Path           string `json:"path,omitempty"`
	CatalogVersion string `json:"catalog_version,omitempty"`
	AsOf           string `json:"as_of,omitempty"` // YYYY-MM-DD the data was current
	AgeDays        *int   `json:"age_days,omitempty"`
	Stale          bool   `json:"stale"`
}

func newKEVSourceInfo(src kev.Source, now time.Time) *kevSourceInfo {
	info := &kevSourceInfo{Origin: string(src.Origin), Path: src.Path, CatalogVersion: src.CatalogVersion, Stale: src.Stale(now)}
	if !src.AsOf.IsZero() {
		info.AsOf = src.AsOf.Format("2006-01-02")
		days := int(src.Age(now).Hours() / 24)
		info.AgeDays = &days
	}
	return info
}

// kevAgeNote renders the KEV data's age for the status line ("" if unknown).
func kevAgeNote(src kev.Source, now time.Time) string {
	if src.AsOf.IsZero() {
		if src.Origin == kev.OriginNone {
			return ""
		}
		return "; age unknown"
	}
	days := int(src.Age(now).Hours() / 24)
	switch {
	case days <= 0:
		return "; current as of today"
	case days == 1:
		return "; 1 day old"
	}
	return fmt.Sprintf("; %d days old", days)
}

func cmdList() *Command {
	var f filters
	var groupFilter string
	var variants, runnable bool
	return &Command{
		Name: "list", Aliases: []string{"ls", "search"},
		Short: "list and filter templates by class, KEV, product surface, CVE and year",
		Usage: "[selector...] [-group H] [-variants] [-ref ID]... [-class C]... [-kev] [-category P] [-cve] [-unverified] [-year YYYY]",
		Long: `A selector is a folder, a contract file, or a template id (substring match
when unique). A ref-shaped selector (CVE-..., GHSA-..., GO-..., VS-...) that
matches no id/file/folder resolves against vuln_refs instead, so
` + "`search CVE-2026-109619`" + ` just works. With no selector every template is listed.

Filters compose (all must match). With no selector, a filter looks at every
template, variant-group members included -- the same set run and build select
for that filter -- while a bare list shows one row per group (its primary)
unless -variants is given. With a selector, filters narrow what it selected.
Finding class, CVE and KEV status are derived
from contract metadata (taxonomy v2) and shown as columns:

  -ref         a specific vuln_refs id -- CVE-, GHSA-, GO- or VS-... (repeatable;
               match any; case-insensitive). Finds secondary refs that are in no id.
  -class       finding class: vuln, misconfig, exposure, default-login,
               weak-crypto (repeatable; a template matches if it carries any)
  -category    product surface -- the top directory level (web-apps,
               web-servers, databases, network-services, iot, misc). Alias -product.
  -cve/-no-cve has / has no CVE id in vuln_refs (boolean; use -ref for a specific id)
  -kev/-no-kev on / not on the CISA Known Exploited Vulnerabilities catalog
  -verified/-unverified
               metadata.verification: unverified targets are statically valid
               but nobody has run their states yet (VERIFIED shows "no"; a
               date is the last ` + "`vulnsuite stamp`" + ` run, "yes" a verified target
               with no recorded run)
  -year        disclosure year (metadata.disclosed, else the CVE-id year)
  -since       disclosed on or after this ISO date (YYYY-MM-DD)

KEV membership is derived by cross-referencing a target's CVEs against the CISA
KEV catalog. The catalog is read from the templates checkout's data/cisa-kev.txt
(kept fresh upstream); -refresh-kev fetches the live CISA feed and caches it as
vulnsuite/cisa-kev.json in the user cache directory (~/.cache on Linux,
~/Library/Caches on macOS, %LocalAppData% on Windows), and that cache is used instead
whenever it holds a newer catalog than the checkout. The status line (and
kev_source in -json) gives the source and its age; data more than 30 days old
gets a warning. Offline with neither present, KEV is shown as "?" and
-kev/-no-kev cannot be used.`,
		Flags: func(fs *flag.FlagSet) {
			f.register(fs)
			fs.StringVar(&groupFilter, "group", "", "only members of this variant group (shows the whole family)")
			fs.BoolVar(&variants, "variants", false, "expand variant groups to all members (default: collapse each group to its primary)")
			fs.BoolVar(&runnable, "runnable", false, "only templates whose requires the current daemon meets (asks the daemon; see `vulnsuite host`)")
		},
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			if err := f.validate(); err != nil {
				return err
			}
			store, err := g.Store()
			if err != nil {
				return err
			}
			if err := checkCategory(store, f.category); err != nil {
				return err
			}
			// Resolve the KEV set always, to populate the column; -kev/-no-kev
			// additionally require it to be known.
			kevSet, kevSrc, err := kev.Resolve(ctx, kev.Options{
				TemplatesDir: store.Root,
				Refresh:      f.refreshKEV,
				Warn:         func(msg string) { g.errorf("warning: %s\n", msg) },
			})
			if err != nil {
				return err
			}
			kevKnown := kevSrc.Origin != kev.OriginNone
			if f.needsKEV() && !kevKnown {
				return fmt.Errorf("cannot filter by KEV: catalog unavailable (offline and no cache). Run with -refresh-kev, or point -templates at a checkout with data/cisa-kev.txt")
			}
			now := time.Now()
			var kevInfo *kevSourceInfo
			if kevKnown {
				kevInfo = newKEVSourceInfo(kevSrc, now)
			}
			if kevSrc.Stale(now) {
				g.errorf("warning: the KEV data is %d days old (%s); refresh it with -refresh-kev or update-templates\n",
					int(kevSrc.Age(now).Hours()/24), kevSrc)
			}
			groupSizes, err := store.Groups()
			if err != nil {
				return err
			}
			// A filter with no selector selects from every template, variant
			// members included, exactly as it does on run and build (#36: "a
			// filter that matches a variant member includes that member
			// regardless of collapse"), so `list <filter>` previews what
			// `run <filter>` / `build <filter>` will stand up. A bare `list`
			// (like -all) still collapses each group to its primary.
			filterAll := len(args) == 0 && groupFilter == "" && f.active()
			expanded := variants || groupFilter != "" || filterAll
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
				paths, err = store.FindMany(nil, true, variants || filterAll)
			default:
				paths, err = store.FindMany(args, false, variants)
			}
			if err != nil {
				return err
			}
			// -runnable preflights each template's requires against the
			// daemon, as run does (CPU flags read once, only if needed).
			var pf *preflighter
			if runnable {
				eng, err := g.Engine(ctx)
				if err != nil {
					return err
				}
				host, err := eng.Info(ctx)
				if err != nil {
					return err
				}
				pf = &preflighter{ctx: ctx, g: g, eng: eng, host: host}
			}
			hidden := 0
			rows := []listRow{} // -json prints [] (not null) when nothing matches
			unloadable := 0
			for _, p := range paths {
				c, err := store.Load(p)
				if err != nil {
					// An unloadable template cannot be filtered, so it is
					// always shown, and the command fails after printing, as
					// validate does. Its row keeps the documented shape: an
					// id (the folder name when even that cannot be read) and
					// arrays, not null.
					unloadable++
					rows = append(rows, listRow{ID: fallbackID(p), Path: p, Error: err.Error(),
						States: []string{}, VulnRefs: []string{}})
					continue
				}
				if !f.match(store, c, p, kevSet, kevKnown) {
					continue
				}
				if pf != nil && !c.Requires.Empty() && pf.decide(c.Requires).Skip() {
					hidden++
					continue
				}
				onKEV := kevSet.Any(c.CVEs())
				row := listRow{
					ID: c.ID(), Group: c.Group(), Variant: c.Variant(), Primary: c.IsPrimary(),
					GroupSize: len(groupSizes[c.Group()]),
					Category:  store.Category(p), Severity: c.Metadata.Severity,
					Class: c.Classes(), CVE: c.IsCVETracked(), Year: c.Year(), Disclosed: c.Metadata.Disclosed,
					States: c.DeclaredStates(), BuildKind: c.BuildKind(contract.StateVulnerable),
					Fidelity: c.Fidelity(), Verification: c.Verification(), VerifiedOn: c.Metadata.VerifiedOn,
					VulnRefs:  c.Metadata.VulnRefs,
					Detection: c.Metadata.Detection, DetectedBy: c.Metadata.DetectedBy, Tags: c.Metadata.Tags,
					HostAccess: runner.HostAccessReason(c) != "",
					Summary:    c.Metadata.Summary, Path: p,
				}
				if !c.Requires.Empty() {
					req := c.Requires
					row.Requires = &req
				}
				if kevKnown {
					v := onKEV
					row.KEV = &v
					row.KEVSource = kevInfo
				}
				rows = append(rows, row)
			}
			loadErr := func() error {
				if unloadable == 0 {
					return nil
				}
				return fmt.Errorf("%d template(s) failed to load; see `vulnsuite validate`", unloadable)
			}
			if g.JSON {
				if err := g.emitJSON(rows); err != nil {
					return err
				}
				return loadErr()
			}
			if len(rows) == 0 {
				g.printf("no templates found in %s\n", store.Root)
				return nil
			}
			tw := tabwriter.NewWriter(g.Stdout, 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tCATEGORY\tGROUP\tSEV\tCLASS\tCVE\tKEV\tFIDELITY\tVERIFIED\tKIND\tREQUIRES\tREFS\tDETECTED BY")
			for _, r := range rows {
				if r.Error != "" {
					fmt.Fprintf(tw, "%s\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t(unloadable: %s)\n", r.ID, r.Error)
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
				req := "-"
				if r.Requires != nil {
					req = requiresText(*r.Requires)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.ID, dash(r.Category), groupCell(r, expanded), r.Severity, dash(strings.Join(r.Class, ",")),
					yesNo(r.CVE), kevCell(r.KEV), r.Fidelity, verifiedCell(r.Verification, r.VerifiedOn), kind, req,
					strings.Join(r.VulnRefs, ","), det)
			}
			tw.Flush()
			g.printf("\n%d templates in %s\n", len(rows), store.Root)
			if runnable {
				g.printf("-runnable: %d hidden that this daemon cannot run (requires.probe is not evaluated: it needs the image)\n", hidden)
			}
			g.printf("KEV source: %s%s\n", kevSrc, kevAgeNote(kevSrc, now))
			if anyHostAccess(rows) {
				g.printf("* needs host access (device/elevated capability); run with -allow-host-access, and only for templates you trust.\n")
			}
			return loadErr()
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

// verifiedCell renders the VERIFIED column: "no" for an unverified target,
// else the date of its last stamped run, or "yes" when none is recorded.
func verifiedCell(verification string, on *contract.VerifiedOn) string {
	switch {
	case verification == contract.VerificationUnverified:
		return "no"
	case on != nil:
		return on.Date
	}
	return "yes"
}

// verifiedText is the info line for a target's verification.
func verifiedText(c *contract.Contract) string {
	vo := c.Metadata.VerifiedOn
	var out string
	if c.IsUnverified() {
		out = "no -- nobody has run this target's states yet (verification: unverified)"
	} else {
		out = "yes"
	}
	if vo != nil {
		host := vo.Host
		if vo.Platform != "" {
			host += " running " + vo.Platform
		}
		if len(vo.CPUFlags) > 0 {
			host += " with " + strings.Join(vo.CPUFlags, ",")
		}
		prefix := "last run"
		if c.IsUnverified() {
			prefix += " (before it was marked unverified)"
		}
		out += fmt.Sprintf("; %s %s: %s verified ok on %s, vulnsuite %s", prefix, vo.Date,
			strings.Join(vo.States, "+"), host, vo.Vulnsuite)
	}
	return out
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
			if err := checkScannerDir("-nuclei-templates", nucleiDir); err != nil {
				return err
			}
			if err := checkScannerDir("-nmap-scripts", nmapDir); err != nil {
				return err
			}
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
				idx, err := loadNucleiIndex(dir)
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
				if findings == nil {
					findings = []validator.Finding{}
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
	var force bool
	return &Command{
		Name: "update-templates", Aliases: []string{"ut"},
		Short: "download or update the community templates (~/vulnsuite-templates)",
		Usage: "[-repo OWNER/NAME] [-ref BRANCH|TAG|COMMIT] [-force]",
		Long: `Fetches ` + templates.DefaultRepo + ` into the templates directory
(-templates, $VULNSUITE_TEMPLATES, the templates repo you are in, or
~/vulnsuite-templates).

A git checkout is pulled (fast-forward only); with -ref, the ref is fetched
from origin and checked out detached (refused while tracked files have
uncommitted changes). A checkout is never replaced: if git is not on PATH the
update fails.

Anything else is replaced by the GitHub archive of -ref (default ` + templates.DefaultBranch + `), but
only when the directory is missing, empty, or was installed by
update-templates before; pass -force to replace any other directory.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&repo, "repo", "", "GitHub repository for archive installs (default "+templates.DefaultRepo+")")
			fs.StringVar(&ref, "ref", "", "branch, tag or commit (default: pull a checkout's branch, or "+templates.DefaultBranch+")")
			fs.BoolVar(&force, "force", false, "replace a non-empty directory update-templates did not install")
		},
		NoArgs: true,
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			dir, err := templates.Resolve(g.TemplatesDir)
			if err != nil {
				return err
			}
			progress := g.Stdout
			if g.JSON {
				progress = g.Stderr // keep stdout valid JSON
			}
			if g.Quiet {
				progress = io.Discard
			}
			dir, version, err := templates.Update(ctx, templates.UpdateOptions{Dir: dir, Repo: repo, Ref: ref, Force: force, Output: progress, Warn: g.Stderr})
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
		NoArgs: true,
		Run: func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error {
			dir, _ := templates.Resolve(g.TemplatesDir)
			if g.JSON {
				return g.emitJSON(map[string]string{"version": resolvedVersion(), "commit": Commit, "date": Date,
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
