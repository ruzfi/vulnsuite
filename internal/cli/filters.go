package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/kev"
	"github.com/ruzfi/vulnsuite/pkg/loader"
)

// filters is the set of metadata predicates shared by list, run and build. A
// filter value left at its zero value does not constrain; the non-zero ones all
// have to match (AND). The same struct backs the command flags and a single
// filter line inside a -f / suite file.
type filters struct {
	tag        string
	fidelity   string
	arch       string
	category   string
	year       string
	since      string
	class      multiFlag
	ref        multiFlag
	onlyKEV    bool
	noKEV      bool
	cve        bool
	noCVE      bool
	refreshKEV bool
}

// register binds the filter flags onto a flag set. It is used both by the
// commands and by the throwaway parser for a filter line in a selector file.
func (f *filters) register(fs *flag.FlagSet) {
	fs.StringVar(&f.tag, "tag", "", "only templates carrying this tag")
	fs.StringVar(&f.fidelity, "fidelity", "", "only templates of this fidelity (real or simulated)")
	fs.StringVar(&f.arch, "arch", "", "only templates that run on this host arch (e.g. amd64, arm64), honouring requires")
	fs.Var(&f.class, "class", "only templates of this finding class (repeatable; match any): vuln, misconfig, exposure, default-login, weak-crypto")
	fs.StringVar(&f.category, "category", "", "only templates in this product surface (top directory level), e.g. web-apps")
	fs.StringVar(&f.category, "product", "", "alias for -category")
	fs.BoolVar(&f.cve, "cve", false, "only templates with a CVE id in vuln_refs")
	fs.BoolVar(&f.noCVE, "no-cve", false, "only templates without a CVE id")
	fs.Var(&f.ref, "ref", "only templates whose vuln_refs contains this id (repeatable; match any; case-insensitive): CVE-, GHSA-, GO-, VS-...")
	fs.BoolVar(&f.onlyKEV, "kev", false, "only templates on the CISA KEV catalog")
	fs.BoolVar(&f.noKEV, "no-kev", false, "only templates not on the CISA KEV catalog")
	fs.StringVar(&f.year, "year", "", "only templates disclosed in this year (YYYY)")
	fs.StringVar(&f.since, "since", "", "only templates disclosed on or after this ISO date (YYYY-MM-DD)")
	fs.BoolVar(&f.refreshKEV, "refresh-kev", false, "fetch the live CISA KEV feed and refresh the local cache before filtering")
}

// active reports whether any predicate is set, i.e. the filter selects a subset
// rather than nothing.
func (f *filters) active() bool {
	return f.tag != "" || f.fidelity != "" || f.arch != "" || f.category != "" ||
		f.year != "" || f.since != "" || len(f.class) > 0 || len(f.ref) > 0 ||
		f.onlyKEV || f.noKEV || f.cve || f.noCVE
}

// needsKEV reports whether evaluating the filter requires the KEV catalog.
func (f *filters) needsKEV() bool { return f.onlyKEV || f.noKEV }

// validate checks the filter values independently of any templates.
func (f *filters) validate() error {
	if f.cve && f.noCVE {
		return usageError{"-cve and -no-cve are mutually exclusive"}
	}
	if f.onlyKEV && f.noKEV {
		return usageError{"-kev and -no-kev are mutually exclusive"}
	}
	for _, cl := range f.class {
		if !has(contract.Classes, cl) {
			return usageError{fmt.Sprintf("unknown -class %q; want one of %s", cl, strings.Join(contract.Classes, ", "))}
		}
	}
	return nil
}

// match reports whether a contract satisfies every set predicate. kevSet/kevKnown
// come from a single resolution shared across all filters.
func (f *filters) match(store *loader.Store, c *contract.Contract, path string, kevSet kev.Set, kevKnown bool) bool {
	if f.tag != "" && !has(c.Metadata.Tags, f.tag) {
		return false
	}
	if f.fidelity != "" && c.Fidelity() != f.fidelity {
		return false
	}
	if f.category != "" && store.Category(path) != f.category {
		return false
	}
	if len(f.class) > 0 && !anyClass(c, f.class) {
		return false
	}
	if len(f.ref) > 0 && !anyRef(c, f.ref) {
		return false
	}
	if f.cve && !c.IsCVETracked() {
		return false
	}
	if f.noCVE && c.IsCVETracked() {
		return false
	}
	if f.onlyKEV || f.noKEV {
		onKEV := kevKnown && kevSet.Any(c.CVEs())
		if f.onlyKEV && !onKEV {
			return false
		}
		if f.noKEV && onKEV {
			return false
		}
	}
	if f.year != "" && c.Year() != f.year {
		return false
	}
	if f.since != "" {
		d := c.DisclosedDate()
		if d == "" || d < f.since {
			return false
		}
	}
	if f.arch != "" {
		req := c.Requires
		ok := len(req.Arch) == 0 || has(req.Arch, f.arch) || (req.EmulationAllowed() && !req.KVM)
		if !ok {
			return false
		}
	}
	return true
}

// resolveKEVFor resolves the CISA KEV catalog when a filter needs it, returning
// the set and whether it is known. When no filter needs KEV it is a no-op.
func resolveKEVFor(ctx context.Context, store *loader.Store, need, refresh bool) (kev.Set, bool, error) {
	if !need {
		return kev.Set{}, false, nil
	}
	set, src, err := kev.Resolve(ctx, kev.Options{TemplatesDir: store.Root, Refresh: refresh})
	if err != nil {
		return kev.Set{}, false, err
	}
	known := src.Origin != kev.OriginNone
	if !known {
		return kev.Set{}, false, fmt.Errorf("cannot filter by KEV: catalog unavailable (offline and no cache). Run with -refresh-kev, or point -templates at a checkout with data/cisa-kev.txt")
	}
	return set, true, nil
}
