// Package scanners links vulnsuite targets to the scanner templates that
// detect them. A target declares them in metadata.detected_by
// ("nuclei:<template-id>"); given a local checkout of nuclei-templates the
// package can also check those ids exist and suggest templates by CVE, so a
// user deploying a target knows which scanner templates to run against it —
// and when none exists, that writing one and contributing it upstream is the
// next step.
package scanners

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// Scanner names used in detected_by refs.
const (
	Nuclei = "nuclei" // projectdiscovery nuclei templates
	Nmap   = "nmap"   // nmap NSE scripts (e.g. nmap:http-aspnet-debug)
)

// Known is the set of recognized scanner names a detected_by ref may use.
var Known = map[string]bool{Nuclei: true, Nmap: true}

// Env names a nuclei-templates checkout.
const Env = "NUCLEI_TEMPLATES"

// UpstreamURL is where new nuclei templates are contributed.
const UpstreamURL = "https://github.com/projectdiscovery/nuclei-templates"

// Ref is one parsed detected_by entry.
type Ref struct {
	Scanner string `json:"scanner"`
	ID      string `json:"id"`
}

func (r Ref) String() string { return r.Scanner + ":" + r.ID }

// Known reports whether the ref names a recognized scanner.
func (r Ref) Known() bool { return Known[r.Scanner] }

// ParseRef splits "scanner:id". A bare id is assumed to be nuclei's.
func ParseRef(s string) Ref {
	scanner, id, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return Ref{Scanner: Nuclei, ID: scanner}
	}
	return Ref{Scanner: strings.ToLower(scanner), ID: id}
}

// Refs parses a contract's detected_by list.
func Refs(c *contract.Contract) []Ref {
	out := make([]Ref, 0, len(c.Metadata.DetectedBy))
	for _, d := range c.Metadata.DetectedBy {
		if r := ParseRef(d); r.ID != "" {
			out = append(out, r)
		}
	}
	return out
}

// Template is one indexed scanner template.
type Template struct {
	ID       string   `json:"id"`
	Path     string   `json:"path"` // relative to the checkout root
	Name     string   `json:"name,omitempty"`
	Severity string   `json:"severity,omitempty"`
	CVEs     []string `json:"cves,omitempty"`
}

// Index is a nuclei-templates checkout, indexed by template id and by CVE.
type Index struct {
	Root  string
	ByID  map[string]*Template
	ByCVE map[string][]*Template
	Count int
}

var cveRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)

// ResolveDir finds a nuclei-templates checkout: flag, then $NUCLEI_TEMPLATES,
// then ~/nuclei-templates. It returns "" when none exists.
func ResolveDir(flag string) string {
	candidates := []string{flag, os.Getenv(Env)}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, "nuclei-templates"))
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

// Load indexes every template under root.
func Load(root string) (*Index, error) {
	idx := &Index{Root: root, ByID: map[string]*Template{}, ByCVE: map[string][]*Template{}}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(d.Name()); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		var doc struct {
			ID   string `yaml:"id"`
			Info struct {
				Name           string `yaml:"name"`
				Severity       string `yaml:"severity"`
				Tags           any    `yaml:"tags"`
				Classification struct {
					CVEID any `yaml:"cve-id"`
				} `yaml:"classification"`
			} `yaml:"info"`
		}
		if yaml.Unmarshal(data, &doc) != nil || doc.ID == "" {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		t := &Template{ID: doc.ID, Path: filepath.ToSlash(rel), Name: doc.Info.Name, Severity: doc.Info.Severity}
		seen := map[string]bool{}
		for _, m := range cveRe.FindAllString(doc.ID+" "+fmt.Sprint(doc.Info.Classification.CVEID)+" "+fmt.Sprint(doc.Info.Tags), -1) {
			cve := strings.ToUpper(m)
			if !seen[cve] {
				seen[cve] = true
				t.CVEs = append(t.CVEs, cve)
				idx.ByCVE[cve] = append(idx.ByCVE[cve], t)
			}
		}
		idx.ByID[t.ID] = t
		idx.Count++
		return nil
	})
	if err != nil {
		return nil, err
	}
	for k := range idx.ByCVE {
		sort.Slice(idx.ByCVE[k], func(i, j int) bool { return idx.ByCVE[k][i].ID < idx.ByCVE[k][j].ID })
	}
	return idx, nil
}

// Link is a declared scanner template, resolved against the index when one
// is available.
type Link struct {
	Ref      Ref       `json:"ref"`
	Verified bool      `json:"verified"` // metadata.detection == scanner
	Template *Template `json:"template,omitempty"`
	// Missing is true when an index was consulted and the id is not in it.
	Missing bool `json:"missing"`
}

// Report is what a target says about scanner coverage.
type Report struct {
	Detection string `json:"detection"` // scanner | custom-only | ""
	// Declared are the detected_by entries.
	Declared []Link `json:"declared"`
	// Suggested are index templates for the target's CVEs that detected_by
	// does not list.
	Suggested []*Template `json:"suggested,omitempty"`
	// Indexed reports whether a nuclei-templates checkout was consulted.
	Indexed bool `json:"indexed"`
}

// Match resolves a contract's scanner links against idx (nil = no checkout).
func Match(c *contract.Contract, idx *Index) Report {
	rep := Report{Detection: c.Metadata.Detection, Indexed: idx != nil}
	declared := map[string]bool{}
	for _, r := range Refs(c) {
		declared[r.ID] = true
		l := Link{Ref: r, Verified: c.Metadata.Detection == "scanner"}
		if idx != nil && r.Scanner == Nuclei {
			if t, ok := idx.ByID[r.ID]; ok {
				l.Template = t
			} else {
				l.Missing = true
			}
		}
		rep.Declared = append(rep.Declared, l)
	}
	if idx != nil {
		seen := map[string]bool{}
		for _, ref := range c.Metadata.VulnRefs {
			for _, t := range idx.ByCVE[strings.ToUpper(ref)] {
				if !declared[t.ID] && !seen[t.ID] {
					seen[t.ID] = true
					rep.Suggested = append(rep.Suggested, t)
				}
			}
		}
	}
	return rep
}

// Covered reports whether at least one scanner template is linked.
func (r Report) Covered() bool { return len(r.Declared) > 0 }

// Lines renders the report for humans: what to run, and what to do when
// nothing exists.
func (r Report) Lines(c *contract.Contract) []string {
	var out []string
	switch {
	case len(r.Declared) > 0:
		for _, l := range r.Declared {
			s := "  " + l.Ref.String()
			switch {
			case l.Template != nil:
				s += "  (" + l.Template.Path + ")"
			case l.Missing:
				s += "  (not found in the local nuclei-templates checkout)"
			}
			if l.Verified {
				s += "  verified"
			}
			out = append(out, s)
		}
		if !r.Declared[0].Verified {
			out = append(out, "  declared, not yet verified: run the scanner against both states and set detection: scanner once it fires on vulnerable and stays silent on patched")
		}
		if len(r.Suggested) > 0 {
			out = append(out, "  also matching this target's CVE(s), not declared yet:")
			for _, t := range r.Suggested {
				out = append(out, "    nuclei:"+t.ID+"  ("+t.Path+")")
			}
		}
	case len(r.Suggested) > 0:
		out = append(out, "  none declared, but the local nuclei-templates checkout has templates for this target's CVE(s):")
		for _, t := range r.Suggested {
			out = append(out, "    nuclei:"+t.ID+"  ("+t.Path+")")
		}
		out = append(out, "  if one fires on vulnerable and stays silent on patched, add it to detected_by in "+relSource(c))
	case r.Detection == "custom-only":
		out = append(out, "  none: this target has no public scanner template (detection: custom-only). It exists to test your own detection.")
		out = append(out, "  if a scanner template could exist for this flaw, writing one and contributing it upstream closes the gap: "+UpstreamURL)
	default:
		out = append(out, "  none known. No scanner template is linked to this target"+cveNote(c, r)+".")
		out = append(out, "  this is a detection gap: a target exists but nothing can find it. Write a nuclei template for it, verify it against")
		out = append(out, "  both states, contribute it upstream ("+UpstreamURL+"), then add nuclei:<id> to detected_by in "+relSource(c))
	}
	return out
}

func cveNote(c *contract.Contract, r Report) string {
	var cves []string
	for _, ref := range c.Metadata.VulnRefs {
		if strings.HasPrefix(ref, "CVE-") {
			cves = append(cves, ref)
		}
	}
	if len(cves) == 0 {
		return ""
	}
	if r.Indexed {
		return ", and the local nuclei-templates checkout has none for " + strings.Join(cves, ", ")
	}
	return " (" + strings.Join(cves, ", ") + "; pass -nuclei-templates DIR to check a local checkout)"
}

func relSource(c *contract.Contract) string {
	if c.SourcePath == "" {
		return "contract.yaml"
	}
	return filepath.Base(filepath.Dir(c.SourcePath)) + "/" + filepath.Base(c.SourcePath)
}
