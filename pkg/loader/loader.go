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

// skipDirs are never descended into while discovering templates.
var skipDirs = map[string]bool{".git": true, "node_modules": true, ".venv": true, "src": true, "files": true, "patches": true}

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
func (s *Store) Find(selector string) ([]string, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, &Error{Path: selector, Message: "empty selector"}
	}
	candidates := []string{selector, filepath.Join(s.Root, selector), filepath.Join(s.Root, "templates", selector)}
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
	// Treat it as an id (exact), then as an id prefix/substring if unique.
	all, err := s.All()
	if err != nil {
		return nil, err
	}
	var exact, fuzzy []string
	for _, f := range all {
		id := peekID(f)
		if id == selector {
			exact = append(exact, f)
		} else if strings.Contains(id, selector) {
			fuzzy = append(fuzzy, f)
		}
	}
	if len(exact) > 0 {
		return exact, nil
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
	return nil, &Error{Path: selector, Message: "no template found (folder, file or id)"}
}

// FindMany resolves several selectors, de-duplicated, preserving order. With
// all set, every template is returned.
func (s *Store) FindMany(selectors []string, all bool) ([]string, error) {
	var paths []string
	if all {
		p, err := s.All()
		if err != nil {
			return nil, err
		}
		paths = p
	} else {
		for _, sel := range selectors {
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

func contractsIn(folder string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(folder, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			if p != folder && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		for _, n := range ContractNames {
			if d.Name() == n {
				abs, _ := filepath.Abs(p)
				out = append(out, abs)
			}
		}
		return nil
	})
	if err != nil {
		return nil, &Error{Path: folder, Message: err.Error(), Err: err}
	}
	sort.Strings(out)
	return out, nil
}

// peekID reads just metadata.id without full validation.
func peekID(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var doc struct {
		Metadata struct {
			ID string `yaml:"id"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return ""
	}
	return doc.Metadata.ID
}

// PeekID exposes peekID for callers that only need ids (e.g. listing).
func PeekID(path string) string { return peekID(path) }
