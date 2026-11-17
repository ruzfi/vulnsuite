package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/loader"
)

// suitePrefix marks a selector that names a curated suite rather than a target.
const suitePrefix = "suite:"

// suiteDir is the subdirectory of the templates root that holds named suites.
const suiteDir = "suites"

// resolver accumulates the selector lines and filter sets gathered from -t, -f
// files and the suites they reference, expanding suites recursively.
type resolver struct {
	store        *loader.Store
	variants     bool
	selectors    []selector
	filterSets   []filters
	visitedSuite map[string]bool
}

// selector is one selector to resolve, with where it came from: "" for the
// command line, "path:line" for a line of a -f or suite file, so a selector
// that matches nothing points at the line to fix.
type selector struct {
	sel    string
	origin string
}

// selectorLine is one line of a selectors file, with its 1-based line number.
type selectorLine struct {
	line int
	text string   // a selector line
	args []string // a filter line's tokens (text is then empty)
}

// atOrigin prefixes err with origin ("path:line: ..."), keeping a usage
// error a usage error so the exit code is unchanged.
func atOrigin(origin string, err error) error {
	if origin == "" || err == nil {
		return err
	}
	var ue usageError
	if errors.As(err, &ue) {
		return usageError{origin + ": " + ue.msg}
	}
	return fmt.Errorf("%s: %w", origin, err)
}

// suiteHandle returns the suite name when sel uses the suite: prefix.
func suiteHandle(sel string) (string, bool) {
	if strings.HasPrefix(sel, suitePrefix) {
		return strings.TrimSpace(strings.TrimPrefix(sel, suitePrefix)), true
	}
	return "", false
}

// addSelector records one selector, expanding a suite: handle in place.
// origin is where the selector came from ("" for the command line).
func (r *resolver) addSelector(sel, origin string) error {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return nil
	}
	if name, ok := suiteHandle(sel); ok {
		return atOrigin(origin, r.addSuite(name))
	}
	r.selectors = append(r.selectors, selector{sel, origin})
	return nil
}

// addSuite expands a named suite (templates/suites/<name>.txt). Cycles are
// broken by skipping a suite already being expanded.
func (r *resolver) addSuite(name string) error {
	if name == "" {
		return usageError{"empty suite name"}
	}
	if r.visitedSuite[name] {
		return nil
	}
	r.visitedSuite[name] = true
	path := filepath.Join(r.store.Root, suiteDir, name+".txt")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no suite %q (expected a selectors file at %s)", name, path)
	}
	return r.addFile(path)
}

// addFile reads a -f / suite file and folds its selector lines and filter lines
// into the resolver. Errors name the file and line.
func (r *resolver) addFile(path string) error {
	lines, err := parseSelectorFile(path)
	if err != nil {
		return err
	}
	for _, l := range lines {
		origin := fmt.Sprintf("%s:%d", path, l.line)
		if l.args != nil {
			f, err := parseFilterLine(l.args)
			if err != nil {
				return atOrigin(origin, err)
			}
			if f.active() {
				r.filterSets = append(r.filterSets, f)
			}
			continue
		}
		if err := r.addSelector(l.text, origin); err != nil {
			return err
		}
	}
	return nil
}

// parseSelectorFile splits a selectors file into selector lines and filter
// lines (lines that begin with '-'), in file order. Blank lines and comments
// (`# ...`, or an inline ` # ...`) are ignored.
func parseSelectorFile(path string) ([]selectorLine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []selectorLine
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") {
			out = append(out, selectorLine{line: i + 1, args: strings.Fields(line)})
			continue
		}
		out = append(out, selectorLine{line: i + 1, text: line})
	}
	return out, nil
}

// parseFilterLine turns a filter line's tokens into a validated filters value.
// Every mistake is a usage error, like the same mistake on the command line.
func parseFilterLine(tokens []string) (filters, error) {
	var f filters
	fs := flag.NewFlagSet("filter", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f.register(fs)
	if err := fs.Parse(tokens); err != nil {
		return f, usageError{fmt.Sprintf("bad filter line %q: %v", strings.Join(tokens, " "), err)}
	}
	if fs.NArg() > 0 {
		return f, usageError{fmt.Sprintf("filter line %q has stray arguments %v", strings.Join(tokens, " "), fs.Args())}
	}
	if err := f.validate(); err != nil {
		return f, err
	}
	return f, nil
}

// resolveTargets turns -t selectors, -f files, suite handles, -all and filter
// predicates into one de-duplicated, order-stable set of contract paths. Every
// selector, every filter set (the command's own filter flags and each filter
// line in a file) selects targets; the result is their union. Filters look at
// every template, variant members included, regardless of group collapse
// (#36); `list <filter>` selects the same set. A template that fails to load
// while filtering is included, so its load error surfaces to the caller.
func resolveTargets(ctx context.Context, store *loader.Store, sel, files []string, all, variants bool, cliFilters filters) ([]string, error) {
	if !all && len(sel) == 0 && len(files) == 0 && !cliFilters.active() {
		return nil, usageError{"pass -t <selector>, -f <file>, a filter (e.g. -class misconfig), or -all"}
	}
	r := &resolver{store: store, variants: variants, visitedSuite: map[string]bool{}}
	if cliFilters.active() {
		if err := cliFilters.validate(); err != nil {
			return nil, err
		}
		r.filterSets = append(r.filterSets, cliFilters)
	}
	for _, s := range sel {
		if err := r.addSelector(s, ""); err != nil {
			return nil, err
		}
	}
	for _, fp := range files {
		if err := r.addFile(fp); err != nil {
			return nil, err
		}
	}

	var out []string
	seen := map[string]bool{}
	add := func(ps []string) {
		for _, p := range ps {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}

	if all {
		ps, err := store.FindMany(nil, true, variants)
		if err != nil {
			return nil, err
		}
		add(ps)
	}
	for _, s := range r.selectors {
		ps, err := store.FindMany([]string{s.sel}, false, variants)
		if err != nil {
			return nil, atOrigin(s.origin, err)
		}
		add(ps)
	}
	if len(r.filterSets) > 0 {
		need, refresh := false, false
		for _, f := range r.filterSets {
			need = need || f.needsKEV()
			refresh = refresh || f.refreshKEV
		}
		kevSet, kevKnown, err := resolveKEVFor(ctx, store, need, refresh)
		if err != nil {
			return nil, err
		}
		allPaths, err := store.All()
		if err != nil {
			return nil, err
		}
		for _, p := range allPaths {
			if seen[p] {
				continue
			}
			c, err := store.Load(p)
			if err != nil {
				// A template that does not load cannot be matched, and must
				// not vanish silently: keep it in the set so the caller's
				// LoadMany reports it as a load error (run fails on it,
				// build counts it as a failure).
				add([]string{p})
				continue
			}
			for _, f := range r.filterSets {
				if f.match(store, c, p, kevSet, kevKnown) {
					add([]string{p})
					break
				}
			}
		}
	}
	return out, nil
}

// gatherSet resolves the full selector/filter/suite surface into loaded
// contracts (plus per-template load errors), for run and build.
func gatherSet(ctx context.Context, store *loader.Store, sel, files []string, all, variants bool, cliFilters filters) ([]*contract.Contract, []error, error) {
	paths, err := resolveTargets(ctx, store, sel, files, all, variants, cliFilters)
	if err != nil {
		return nil, nil, err
	}
	cs, errs := store.LoadMany(paths)
	return cs, errs, nil
}
