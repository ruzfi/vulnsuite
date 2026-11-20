// Package loader discovers and loads target templates from a templates tree,
// a single folder, a file, or an id.
package loader

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// ContractNames are the file names a template contract may use.
var ContractNames = []string{"contract.yaml", "contract.yml", "template.yaml"}

// skipDirs are never descended into while discovering templates (nor is any
// dot-directory: .git, .github, .venv, a .trash folder...).
var skipDirs = map[string]bool{"node_modules": true}

// contentDirs hold a template's own build inputs. They are skipped only inside a
// contract folder, so a category that happens to be called "files" is still
// discovered.
var contentDirs = map[string]bool{"src": true, "files": true, "patches": true}

// Error is a load/discovery error tied to a path or selector.
type Error struct {
	Path    string
	Message string
	Err     error
}

func (e *Error) Error() string { return e.Path + ": " + e.Message }
func (e *Error) Unwrap() error { return e.Err }

// Store is a templates root.
type Store struct {
	Root string
}

// New returns a Store for root (made absolute).
func New(root string) *Store {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	return &Store{Root: abs}
}

// All returns every contract file under the root, sorted.
func (s *Store) All() ([]string, error) {
	return contractsIn(s.Root)
}

// Find resolves a selector (a folder, a file, a path relative to the root, or
// an id) to contract files.
//
// A selector is read as a path relative to the working directory only when it
// looks like one (see IsPathSelector); a bare name such as "grafana" is always
// resolved within the templates root, so a file or folder of that name in the
// working directory never shadows a template.
func (s *Store) Find(selector string) ([]string, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, &Error{Path: selector, Message: "empty selector"}
	}
	var candidates []string
	if IsPathSelector(selector) {
		candidates = append(candidates, expandHome(selector))
	}
	if !filepath.IsAbs(selector) {
		candidates = append(candidates, filepath.Join(s.Root, selector), filepath.Join(s.Root, "templates", selector))
	}
	for _, c := range candidates {
		info, err := os.Stat(c)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			abs, _ := filepath.Abs(c)
			return []string{abs}, nil
		}
		found, err := contractsIn(c)
		if err != nil {
			return nil, err
		}
		if len(found) > 0 {
			return found, nil
		}
	}
	// Resolution precedence for a non-path selector: exact id -> exact group
	// (yields the primary) -> matching vuln_ref -> unique id substring.
	all, err := s.All()
	if err != nil {
		return nil, err
	}
	refShaped := contract.IsVulnRef(selector)
	var exact, fuzzy, refMatch []string
	var group []GroupMember
	var unreadable []string
	for _, f := range all {
		p, perr := peek(f)
		if perr != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", f, perr))
			continue
		}
		switch {
		case p.ID == selector:
			exact = append(exact, f)
		case strings.Contains(p.ID, selector):
			fuzzy = append(fuzzy, f)
		}
		if p.Group == selector {
			group = append(group, GroupMember{Path: f, ID: p.ID, Variant: p.Variant, Primary: p.Primary})
		}
		if refShaped {
			for _, r := range p.Refs {
				if strings.EqualFold(r, selector) {
					refMatch = append(refMatch, f)
					break
				}
			}
		}
	}
	if len(exact) > 0 {
		return exact, nil
	}
	// An exact group handle resolves to the group's primary (expand with
	// -variants via FindMany).
	if len(group) > 0 {
		primary, ok := primaryOf(group)
		if !ok {
			ids := make([]string, 0, len(group))
			for _, m := range group {
				ids = append(ids, m.ID)
			}
			sort.Strings(ids)
			return nil, &Error{Path: selector, Message: fmt.Sprintf("group %q has no primary; mark exactly one member primary: true (members: %s)", selector, strings.Join(ids, ", "))}
		}
		return []string{primary}, nil
	}
	// A ref-shaped selector that matches vuln_refs resolves to those templates,
	// even when several match (a clean multi-row list, not an ambiguity error).
	if len(refMatch) > 0 {
		return refMatch, nil
	}
	if len(fuzzy) == 1 {
		return fuzzy, nil
	}
	if len(fuzzy) > 1 {
		ids := make([]string, 0, len(fuzzy))
		for _, f := range fuzzy {
			ids = append(ids, peekID(f))
		}
		return nil, &Error{Path: selector, Message: "ambiguous selector; matches " + strings.Join(ids, ", ")}
	}
	msg := "no template found (folder, file, id, group or vuln_ref)"
	if len(unreadable) > 0 {
		// The wanted template may be one that does not parse; say so rather
		// than hiding the YAML error behind "not found".
		msg += fmt.Sprintf("; %d template(s) could not be read and may be the one you meant:\n  %s",
			len(unreadable), strings.Join(unreadable, "\n  "))
	}
	return nil, &Error{Path: selector, Message: msg}
}

// IsPathSelector reports whether a selector names a filesystem path rather
// than a template id, group or category: it contains a path separator, starts
// with "." or "~", is absolute, or ends in a contract-file extension (.yaml,
// .yml).
func IsPathSelector(selector string) bool {
	if strings.ContainsRune(selector, '/') || strings.ContainsRune(selector, filepath.Separator) {
		return true
	}
	if strings.HasPrefix(selector, ".") || strings.HasPrefix(selector, "~") {
		return true
	}
	if filepath.IsAbs(selector) || filepath.VolumeName(selector) != "" {
		return true
	}
	switch strings.ToLower(filepath.Ext(selector)) {
	case ".yaml", ".yml":
		return true
	}
	return false
}

// expandHome expands a leading "~/" (a quoted selector the shell left alone).
func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~"); ok && (rest == "" || rest[0] == '/' || rest[0] == filepath.Separator) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}

// FindMany resolves several selectors, de-duplicated, preserving order.
//
// With all set, every template is returned when variants is set; otherwise each
// group is collapsed to its primary (one target per family) while ungrouped
// targets are all kept. With explicit selectors, variants expands a selector
// that names a group to all its members; it is a no-op on any selector that
// resolves to a single target.
func (s *Store) FindMany(selectors []string, all, variants bool) ([]string, error) {
	var paths []string
	if all {
		p, err := s.All()
		if err != nil {
			return nil, err
		}
		if variants {
			paths = p
		} else {
			if paths, err = s.collapseToPrimaries(p); err != nil {
				return nil, err
			}
		}
	} else {
		var grps map[string][]GroupMember
		if variants {
			g, err := s.groups()
			if err != nil {
				return nil, err
			}
			grps = g
		}
		for _, sel := range selectors {
			if variants {
				if members, ok := grps[strings.TrimSpace(sel)]; ok {
					for _, m := range members {
						paths = append(paths, m.Path)
					}
					continue
				}
			}
			p, err := s.Find(sel)
			if err != nil {
				return nil, err
			}
			paths = append(paths, p...)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// collapseToPrimaries keeps every ungrouped path and, for grouped paths, only
// each group's primary; order is preserved. A group with no resolvable primary
// (invalid; the validator flags it) keeps all its members so nothing silently
// vanishes.
func (s *Store) collapseToPrimaries(paths []string) ([]string, error) {
	grps, err := s.groups()
	if err != nil {
		return nil, err
	}
	handleOf := map[string]string{} // path -> group handle
	primary := map[string]string{}  // handle -> primary path
	for h, members := range grps {
		if p, ok := primaryOf(members); ok {
			primary[h] = p
		}
		for _, m := range members {
			handleOf[m.Path] = h
		}
	}
	var out []string
	for _, p := range paths {
		h, grouped := handleOf[p]
		if !grouped {
			out = append(out, p)
			continue
		}
		pp, ok := primary[h]
		if !ok || p == pp {
			out = append(out, p)
		}
	}
	return out, nil
}

// Category returns the product-surface category of a contract: the top
// directory level under the store root (e.g. web-apps, databases, iot). It is
// "" when the contract sits directly in the root or outside it.
func (s *Store) Category(contractPath string) string {
	abs, err := filepath.Abs(contractPath)
	if err != nil {
		abs = contractPath
	}
	rel, err := filepath.Rel(s.Root, filepath.Dir(abs))
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == "" || strings.HasPrefix(rel, "..") {
		return ""
	}
	return strings.SplitN(rel, "/", 2)[0]
}

// Load parses one contract file.
func (s *Store) Load(path string) (*contract.Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &Error{Path: path, Message: err.Error(), Err: err}
	}
	c, err := contract.Parse(data)
	if err != nil {
		return nil, &Error{Path: path, Message: err.Error(), Err: err}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	c.SourcePath = abs
	c.Folder = filepath.Dir(abs)
	return c, nil
}

// LoadSelector resolves a selector that must match exactly one template.
func (s *Store) LoadSelector(selector string) (*contract.Contract, error) {
	files, err := s.Find(selector)
	if err != nil {
		return nil, err
	}
	if len(files) > 1 {
		return nil, &Error{Path: selector, Message: fmt.Sprintf("selector matched %d templates; be specific", len(files))}
	}
	return s.Load(files[0])
}

// LoadMany loads every path, returning the contracts that loaded and the
// errors for those that did not.
func (s *Store) LoadMany(paths []string) ([]*contract.Contract, []error) {
	var out []*contract.Contract
	var errs []error
	for _, p := range paths {
		c, err := s.Load(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, c)
	}
	return out, errs
}

// ByID loads every template and indexes it by id.
func (s *Store) ByID() (map[string]*contract.Contract, error) {
	paths, err := s.All()
	if err != nil {
		return nil, err
	}
	out := map[string]*contract.Contract{}
	for _, p := range paths {
		c, err := s.Load(p)
		if err != nil {
			continue
		}
		out[c.ID()] = c
	}
	return out, nil
}

// contractsIn discovers contract files under folder. Each folder contributes
// at most one contract (the first of ContractNames present); dot-directories
// and skipDirs are never entered, contentDirs are skipped inside a contract
// folder, and symlinked directories are followed once (a directory reached
// again through a link loop is not re-entered).
func contractsIn(folder string) ([]string, error) {
	root, err := filepath.Abs(folder)
	if err != nil {
		root = folder
	}
	var out []string
	visited := map[string]bool{}
	var walk func(dir string, top bool) error
	walk = func(dir string, top bool) error {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			if visited[real] {
				return nil
			}
			visited[real] = true
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !top || errors.Is(err, fs.ErrPermission) {
				return nil // an unreadable subfolder is skipped, as before
			}
			return err
		}
		files := map[string]bool{}
		for _, e := range entries {
			if !e.IsDir() {
				files[e.Name()] = true
			}
		}
		inContract := false
		for _, n := range ContractNames {
			if files[n] {
				out = append(out, filepath.Join(dir, n))
				inContract = true
				break
			}
		}
		for _, e := range entries {
			name := e.Name()
			isDir := e.IsDir()
			if e.Type()&fs.ModeSymlink != 0 {
				info, err := os.Stat(filepath.Join(dir, name))
				isDir = err == nil && info.IsDir()
			}
			if !isDir || strings.HasPrefix(name, ".") || skipDirs[name] || (inContract && contentDirs[name]) {
				continue
			}
			if err := walk(filepath.Join(dir, name), false); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, true); err != nil {
		return nil, &Error{Path: folder, Message: err.Error(), Err: err}
	}
	sort.Strings(out)
	return out, nil
}

// peeked is the subset of metadata read for cheap resolution over a whole tree,
// without a full parse or validation.
type peeked struct {
	ID      string
	Refs    []string
	Group   string
	Variant string
	Primary bool
}

// peekID reads just metadata.id without full validation ("" when unreadable).
func peekID(path string) string {
	p, _ := peek(path)
	return p.ID
}

// peek reads the resolution-relevant metadata (id, vuln_refs, group, variant,
// primary) without full validation, for cheap id/reference/group resolution
// over a whole tree. The error is the read or YAML error, if any.
func peek(path string) (peeked, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return peeked{}, err
	}
	var doc struct {
		Metadata struct {
			ID       string   `yaml:"id"`
			VulnRefs []string `yaml:"vuln_refs"`
			Group    string   `yaml:"group"`
			Variant  string   `yaml:"variant"`
			Primary  bool     `yaml:"primary"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return peeked{}, fmt.Errorf("invalid YAML: %s", strings.TrimSpace(yaml.FormatError(err, false, false)))
	}
	m := doc.Metadata
	return peeked{ID: m.ID, Refs: m.VulnRefs, Group: m.Group, Variant: m.Variant, Primary: m.Primary}, nil
}

// PeekID exposes peekID for callers that only need ids (e.g. listing).
func PeekID(path string) string { return peekID(path) }

// GroupMember is one target within a variant group.
type GroupMember struct {
	Path    string
	ID      string
	Variant string
	Primary bool
}

// groups indexes every grouped contract under the root by its group handle.
// Members within a handle are sorted by path (the order All returns).
func (s *Store) groups() (map[string][]GroupMember, error) {
	all, err := s.All()
	if err != nil {
		return nil, err
	}
	out := map[string][]GroupMember{}
	for _, f := range all {
		p, _ := peek(f) // an unreadable contract is in no group; Load reports it
		if p.Group == "" {
			continue
		}
		out[p.Group] = append(out[p.Group], GroupMember{Path: f, ID: p.ID, Variant: p.Variant, Primary: p.Primary})
	}
	return out, nil
}

// Groups returns every variant group under the root, indexed by handle.
func (s *Store) Groups() (map[string][]GroupMember, error) { return s.groups() }

// GroupMembers returns the members of a group handle and whether the handle
// names a known group. Members are ordered by path, primary first.
func (s *Store) GroupMembers(handle string) ([]GroupMember, bool, error) {
	grps, err := s.groups()
	if err != nil {
		return nil, false, err
	}
	members, ok := grps[strings.TrimSpace(handle)]
	if !ok {
		return nil, false, nil
	}
	sort.SliceStable(members, func(i, j int) bool {
		if members[i].Primary != members[j].Primary {
			return members[i].Primary
		}
		return members[i].Path < members[j].Path
	})
	return members, true, nil
}

// primaryOf returns the primary member's path: the one marked primary, or the
// lone member of a single-member group (a nickname). ok is false when a
// multi-member group marks no primary.
func primaryOf(members []GroupMember) (path string, ok bool) {
	if len(members) == 1 {
		return members[0].Path, true
	}
	for _, m := range members {
		if m.Primary {
			return m.Path, true
		}
	}
	return "", false
}

// Shadowed returns the other contract files in the folder of the contract at
// path: discovery uses only the first of ContractNames present in a folder, so
// any other one is silently ignored. Callers (validate) report them.
func Shadowed(path string) []string {
	dir, self := filepath.Dir(path), filepath.Base(path)
	var out []string
	for _, n := range ContractNames {
		if n == self {
			continue
		}
		if info, err := os.Stat(filepath.Join(dir, n)); err == nil && info.Mode().IsRegular() {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out
}
