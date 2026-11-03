// Package kev resolves the CISA Known Exploited Vulnerabilities (KEV) catalog
// into a set of CVE ids, so the CLI can filter targets by KEV membership.
//
// KEV is derived, never stored per target: a target is "on KEV" when any of its
// CVE vuln_refs is in the catalog, and the catalog changes upstream (CISA adds
// and removes entries). The set is sourced, in order:
//
//   - the templates checkout's data/cisa-kev.txt (the source of truth, a
//     CVE-id snapshot kept fresh by the templates repo's cisa-kev-sync Action);
//   - a local cache (~/.cache/vulnsuite/cisa-kev.json), when the templates file
//     is absent;
//   - empty, offline, when neither exists — the caller warns and --kev matches
//     nothing.
//
// Refresh forces a network fetch of the CISA feed and refreshes the cache
// (Option B: an explicit --refresh-kev override).
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// FeedURL is the public CISA KEV JSON feed.
const FeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// cveRe matches a bare CVE id anywhere in a line (case-insensitive; ids are
// upper-cased on insertion).
var cveRe = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

// Set is a set of KEV-listed CVE ids (upper-cased).
type Set map[string]bool

// Contains reports whether cve is in the KEV set (case-insensitive).
func (s Set) Contains(cve string) bool { return s[strings.ToUpper(cve)] }

// Any reports whether any of cves is in the KEV set.
func (s Set) Any(cves []string) bool {
	for _, c := range cves {
		if s.Contains(c) {
			return true
		}
	}
	return false
}

// Len is the number of CVE ids in the set.
func (s Set) Len() int { return len(s) }

// Origin names where a resolved set came from, for user-facing messages.
type Origin string

// Origins.
const (
	OriginTemplates Origin = "templates" // data/cisa-kev.txt from the templates checkout
	OriginCache     Origin = "cache"     // the local ~/.cache cache
	OriginNetwork   Origin = "network"   // a fresh fetch of the CISA feed
	OriginNone      Origin = "none"      // no source available (offline, empty set)
)

// Source describes a resolved set's provenance.
type Source struct {
	Origin  Origin
	Path    string // file path or URL, when applicable
	Fetched string // ISO timestamp for cache/network sources
}

// String renders the source for a status line.
func (s Source) String() string {
	switch s.Origin {
	case OriginTemplates:
		return "templates " + s.Path
	case OriginCache:
		at := ""
		if s.Fetched != "" {
			at = " (fetched " + s.Fetched + ")"
		}
		return "cache " + s.Path + at
	case OriginNetwork:
		return "CISA feed " + s.Path
	default:
		return "unavailable (offline)"
	}
}

// Options configures Resolve.
type Options struct {
	// TemplatesDir is the templates checkout; its data/cisa-kev.txt is the
	// source of truth when present.
	TemplatesDir string
	// Refresh forces a network fetch and rewrites the cache (Option B).
	Refresh bool
	// CacheDir overrides the default ~/.cache/vulnsuite cache location.
	CacheDir string
	// Client overrides the HTTP client used for a fetch (tests).
	Client *http.Client
	// FeedURL overrides the CISA feed URL (tests); empty uses FeedURL.
	FeedURL string
	// Now overrides the clock used for cache timestamps (tests).
	Now func() time.Time
}

func (o Options) feedURL() string {
	if o.FeedURL != "" {
		return o.FeedURL
	}
	return FeedURL
}

// CachePath is the resolved cache file path for these options.
func (o Options) cachePath() (string, error) {
	dir := o.CacheDir
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, "vulnsuite")
	}
	return filepath.Join(dir, "cisa-kev.json"), nil
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Resolve loads the KEV CVE-id set per the sourcing rules. It never errors on a
// missing source; it only errors when Refresh is set and the fetch fails, or on
// an unreadable existing file.
func Resolve(ctx context.Context, opts Options) (Set, Source, error) {
	cachePath, cacheErr := opts.cachePath()

	if opts.Refresh {
		if cacheErr != nil {
			return nil, Source{}, cacheErr
		}
		url := opts.feedURL()
		set, err := fetch(ctx, opts.Client, url)
		if err != nil {
			return nil, Source{}, fmt.Errorf("refresh KEV from CISA feed: %w", err)
		}
		fetched := opts.now().UTC().Format(time.RFC3339)
		// A fresh set is still usable even if the cache write fails.
		_ = writeCache(cachePath, set, string(OriginNetwork), fetched)
		return set, Source{Origin: OriginNetwork, Path: url, Fetched: fetched}, nil
	}

	// Source of truth: the templates checkout's snapshot.
	if opts.TemplatesDir != "" {
		txt := filepath.Join(opts.TemplatesDir, "data", "cisa-kev.txt")
		if data, err := os.ReadFile(txt); err == nil {
			return parseTxt(data), Source{Origin: OriginTemplates, Path: txt}, nil
		} else if !os.IsNotExist(err) {
			return nil, Source{}, fmt.Errorf("read %s: %w", txt, err)
		}
	}

	// Fallback: the local cache from an earlier --refresh-kev.
	if cacheErr == nil {
		if set, fetched, err := loadCache(cachePath); err == nil {
			return set, Source{Origin: OriginCache, Path: cachePath, Fetched: fetched}, nil
		} else if !os.IsNotExist(err) {
			return nil, Source{}, fmt.Errorf("read KEV cache %s: %w", cachePath, err)
		}
	}

	// Offline, no source: an empty set. The caller warns; --kev matches nothing.
	return Set{}, Source{Origin: OriginNone}, nil
}

// parseTxt reads a newline/space-delimited CVE-id snapshot, skipping blanks and
// '#' comments. Any CVE id on a line is kept.
func parseTxt(data []byte) Set {
	set := Set{}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, id := range cveRe.FindAllString(line, -1) {
			set[strings.ToUpper(id)] = true
		}
	}
	return set
}

// cacheFile is vulnsuite's own compact cache of the KEV CVE-id set.
type cacheFile struct {
	Fetched string   `json:"fetched"`
	Source  string   `json:"source"`
	CVEs    []string `json:"cves"`
}

func loadCache(path string) (Set, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var cf cacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, "", fmt.Errorf("corrupt KEV cache: %w", err)
	}
	set := Set{}
	for _, id := range cf.CVEs {
		if cveRe.MatchString(id) {
			set[strings.ToUpper(id)] = true
		}
	}
	return set, cf.Fetched, nil
}

func writeCache(path string, set Set, source, fetched string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	cf := cacheFile{Fetched: fetched, Source: source, CVEs: sortedKeys(set)}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// feedDoc is the subset of the CISA KEV JSON feed we read.
type feedDoc struct {
	Vulnerabilities []struct {
		CveID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

func fetch(ctx context.Context, client *http.Client, url string) (Set, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vulnsuite")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	var doc feedDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse CISA feed: %w", err)
	}
	set := Set{}
	for _, v := range doc.Vulnerabilities {
		if cveRe.MatchString(v.CveID) {
			set[strings.ToUpper(v.CveID)] = true
		}
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("CISA feed contained no CVE ids")
	}
	return set, nil
}

func sortedKeys(set Set) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out) // sorted ids keep the cache diff-friendly
	return out
}
