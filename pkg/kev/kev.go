// Package kev resolves the CISA Known Exploited Vulnerabilities (KEV) catalog
// into a set of CVE ids, so the CLI can filter targets by KEV membership.
//
// KEV is derived, never stored per target: a target is "on KEV" when any of its
// CVE vuln_refs is in the catalog, and the catalog changes upstream (CISA adds
// and removes entries). The set is sourced, in order:
//
//   - the templates checkout's data/cisa-kev.txt (the source of truth, a
//     CVE-id snapshot kept fresh by the templates repo's cisa-kev-sync Action),
//     unless the local cache holds a newer catalog;
//   - a local cache (~/.cache/vulnsuite/cisa-kev.json), when the templates file
//     is absent or older than the cache;
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

// cveRe matches a bare CVE id within a line (case-insensitive; ids are
// upper-cased on insertion). The word boundaries keep it from taking a prefix of
// a longer token (CVE-2021-12345678 is not CVE-2021-1234567).
var cveRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)

// cveExactRe matches a value that is exactly one CVE id, for whole-value
// checks of cache and feed entries.
var cveExactRe = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,7}$`)

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
	// CatalogVersion is CISA's catalogVersion (e.g. 2026.11.13) of the data,
	// when known: the templates snapshot's header, or the feed's field.
	CatalogVersion string
	// AsOf is when the data was current: the catalogVersion date, else the
	// fetch time. Zero when unknown (a snapshot without a header).
	AsOf time.Time
}

// StaleAfter is the age past which KEV data is reported as stale. CISA adds
// entries every few days, so a month-old set is likely missing some.
const StaleAfter = 30 * 24 * time.Hour

// Age is how old the data is at now (0 when AsOf is unknown).
func (s Source) Age(now time.Time) time.Duration {
	if s.AsOf.IsZero() {
		return 0
	}
	return now.Sub(s.AsOf)
}

// Stale reports whether the data is known to be older than StaleAfter.
func (s Source) Stale(now time.Time) bool {
	return !s.AsOf.IsZero() && s.Age(now) > StaleAfter
}

// String renders the source for a status line.
func (s Source) String() string {
	var notes []string
	if s.CatalogVersion != "" {
		notes = append(notes, "catalog "+s.CatalogVersion)
	}
	if s.Fetched != "" && s.Origin != OriginNetwork {
		notes = append(notes, "fetched "+s.Fetched)
	}
	note := ""
	if len(notes) > 0 {
		note = " (" + strings.Join(notes, ", ") + ")"
	}
	switch s.Origin {
	case OriginTemplates:
		return "templates " + s.Path + note
	case OriginCache:
		return "cache " + s.Path + note
	case OriginNetwork:
		return "CISA feed " + s.Path + note
	default:
		return "unavailable (offline)"
	}
}

// catalogDate parses a CISA catalogVersion (2026.11.13) as a date.
func catalogDate(v string) time.Time {
	t, err := time.Parse("2006.01.02", strings.TrimSpace(v))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// asOf is when data with this catalog version, fetched at fetched (RFC 3339),
// was current: the catalog date when known, else the fetch time.
func asOf(catalogVersion, fetched string) time.Time {
	if t := catalogDate(catalogVersion); !t.IsZero() {
		return t
	}
	t, _ := time.Parse(time.RFC3339, fetched)
	return t
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
	// Warn receives non-fatal problems (a corrupt cache, an empty snapshot).
	// Nil writes them to stderr.
	Warn func(msg string)
}

func (o Options) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if o.Warn != nil {
		o.Warn(msg)
		return
	}
	fmt.Fprintln(os.Stderr, "warning: "+msg)
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
// an unreadable templates snapshot. A corrupt or unreadable cache is treated as
// missing (with a warning), and an empty templates snapshot falls through to
// the cache, so a bad file cannot break every listing.
func Resolve(ctx context.Context, opts Options) (Set, Source, error) {
	cachePath, cacheErr := opts.cachePath()

	if opts.Refresh {
		if cacheErr != nil {
			return nil, Source{}, cacheErr
		}
		url := opts.feedURL()
		set, version, err := fetch(ctx, opts.Client, url)
		if err != nil {
			return nil, Source{}, fmt.Errorf("refresh KEV from CISA feed: %w", err)
		}
		fetched := opts.now().UTC().Format(time.RFC3339)
		// A fresh set is still usable even if the cache write fails.
		_ = writeCache(cachePath, set, string(OriginNetwork), fetched, version)
		return set, Source{Origin: OriginNetwork, Path: url, Fetched: fetched, CatalogVersion: version, AsOf: asOf(version, fetched)}, nil
	}

	// The local cache from an earlier --refresh-kev.
	var cacheSet Set
	var cacheSrc Source
	var cacheLoadErr error = os.ErrNotExist
	if cacheErr == nil {
		var cf cacheFile
		if cacheSet, cf, cacheLoadErr = loadCache(cachePath); cacheLoadErr == nil {
			cacheSrc = Source{Origin: OriginCache, Path: cachePath, Fetched: cf.Fetched,
				CatalogVersion: cf.CatalogVersion, AsOf: asOf(cf.CatalogVersion, cf.Fetched)}
		}
	}

	// Source of truth: the templates checkout's snapshot, unless the cache is
	// known to hold a newer catalog (a recent -refresh-kev against an old
	// checkout).
	if opts.TemplatesDir != "" {
		txt := filepath.Join(opts.TemplatesDir, "data", "cisa-kev.txt")
		if data, err := os.ReadFile(txt); err == nil {
			if set := parseTxt(data); set.Len() > 0 {
				version := txtCatalogVersion(data)
				src := Source{Origin: OriginTemplates, Path: txt, CatalogVersion: version, AsOf: catalogDate(version)}
				if cacheLoadErr == nil && cacheSet.Len() > 0 && !src.AsOf.IsZero() && cacheSrc.AsOf.After(src.AsOf) {
					return cacheSet, cacheSrc, nil
				}
				return set, src, nil
			}
			// An empty snapshot (e.g. a failed sync committed an empty file) is
			// not authoritative: fall through to the cache.
			opts.warn("%s contains no CVE ids; ignoring it", txt)
		} else if !os.IsNotExist(err) {
			return nil, Source{}, fmt.Errorf("read %s: %w", txt, err)
		}
	}

	// Fallback: the cache.
	if cacheLoadErr == nil {
		return cacheSet, cacheSrc, nil
	} else if !os.IsNotExist(cacheLoadErr) {
		// A truncated or unreadable cache is treated as missing.
		opts.warn("ignoring KEV cache %s: %v (run with -refresh-kev to rebuild it)", cachePath, cacheLoadErr)
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

// catalogVersionRe finds the snapshot header written by the templates repo's
// sync: "# catalogVersion: 2026.11.13  count: 1781".
var catalogVersionRe = regexp.MustCompile(`(?m)^#\s*catalogVersion:\s*(\S+)`)

// txtCatalogVersion returns the snapshot's catalogVersion header ("" if none).
func txtCatalogVersion(data []byte) string {
	if m := catalogVersionRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// cacheFile is vulnsuite's own compact cache of the KEV CVE-id set.
type cacheFile struct {
	Fetched        string   `json:"fetched"`
	Source         string   `json:"source"`
	CatalogVersion string   `json:"catalog_version,omitempty"`
	CVEs           []string `json:"cves"`
}

func loadCache(path string) (Set, cacheFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, cacheFile{}, err
	}
	var cf cacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, cacheFile{}, fmt.Errorf("corrupt KEV cache: %w", err)
	}
	set := Set{}
	for _, id := range cf.CVEs {
		if cveExactRe.MatchString(id) {
			set[strings.ToUpper(id)] = true
		}
	}
	return set, cf, nil
}

func writeCache(path string, set Set, source, fetched, catalogVersion string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	cf := cacheFile{Fetched: fetched, Source: source, CatalogVersion: catalogVersion, CVEs: sortedKeys(set)}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	// Write a temp file in the same directory and rename it into place, so a
	// crash or a concurrent -refresh-kev never leaves a truncated cache.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cisa-kev-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// feedDoc is the subset of the CISA KEV JSON feed we read.
type feedDoc struct {
	CatalogVersion  string `json:"catalogVersion"`
	Vulnerabilities []struct {
		CveID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

func fetch(ctx context.Context, client *http.Client, url string) (Set, string, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "vulnsuite")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, "", err
	}
	var doc feedDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("parse CISA feed: %w", err)
	}
	set := Set{}
	for _, v := range doc.Vulnerabilities {
		if cveExactRe.MatchString(v.CveID) {
			set[strings.ToUpper(v.CveID)] = true
		}
	}
	if len(set) == 0 {
		return nil, "", fmt.Errorf("CISA feed contained no CVE ids")
	}
	return set, doc.CatalogVersion, nil
}

func sortedKeys(set Set) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out) // sorted ids keep the cache diff-friendly
	return out
}
