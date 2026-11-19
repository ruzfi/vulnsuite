package scanners

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// indexFormat versions the cache file; bump it when Template or the way Load
// derives its fields changes, so older caches are rebuilt.
const indexFormat = 1

// indexCache is the on-disk form of an Index.
type indexCache struct {
	Format      int         `json:"format"`
	Root        string      `json:"root"`
	Fingerprint string      `json:"fingerprint"`
	Templates   []*Template `json:"templates"` // in walk order
}

// LoadCached is Load with a cache: the index of root is stored under cacheDir
// and reused while the checkout's template files are unchanged. The cache is
// keyed by a fingerprint of every template file's path, size and mtime, taken
// with the same walk Load does, so a pull, a checkout or a local edit
// invalidates it, without reading or parsing any file. Indexing a full
// nuclei-templates checkout parses ~14k YAML files and takes seconds; the
// fingerprint walk only stats them. A cache that cannot be read or written is
// ignored: the index is then built as Load builds it.
func LoadCached(root, cacheDir string) (*Index, error) {
	if cacheDir == "" {
		return Load(root)
	}
	fp, err := fingerprint(root)
	if err != nil {
		return Load(root)
	}
	sum := sha256.Sum256([]byte(root))
	path := filepath.Join(cacheDir, "nuclei-index-"+hex.EncodeToString(sum[:8])+".json")
	if idx := readIndexCache(path, root, fp); idx != nil {
		return idx, nil
	}
	idx, err := Load(root)
	if err != nil {
		return nil, err
	}
	writeIndexCache(path, idx, fp)
	return idx, nil
}

// fingerprint hashes the path, size and mtime of every file Load would read.
func fingerprint(root string) (string, error) {
	h := sha256.New()
	var buf [16]byte
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Load skips unreadable entries too
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
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		h.Write([]byte(filepath.ToSlash(rel)))
		h.Write([]byte{0})
		binary.LittleEndian.PutUint64(buf[:8], uint64(info.Size()))
		binary.LittleEndian.PutUint64(buf[8:], uint64(info.ModTime().UnixNano()))
		h.Write(buf[:])
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readIndexCache(path, root, fp string) *Index {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var c indexCache
	if json.Unmarshal(data, &c) != nil || c.Format != indexFormat || c.Root != root || c.Fingerprint != fp {
		return nil
	}
	idx := &Index{Root: root, ByID: map[string]*Template{}, ByCVE: map[string][]*Template{}}
	for _, t := range c.Templates {
		if t == nil || t.ID == "" {
			return nil
		}
		if _, dup := idx.ByID[t.ID]; dup {
			return nil
		}
		idx.ByID[t.ID] = t
		idx.Count++
		for _, cve := range t.CVEs {
			idx.ByCVE[cve] = append(idx.ByCVE[cve], t)
		}
	}
	for k := range idx.ByCVE {
		sort.Slice(idx.ByCVE[k], func(i, j int) bool { return idx.ByCVE[k][i].ID < idx.ByCVE[k][j].ID })
	}
	return idx
}

func writeIndexCache(path string, idx *Index, fp string) {
	ts := make([]*Template, 0, len(idx.ByID))
	for _, t := range idx.ByID {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Path < ts[j].Path })
	data, err := json.Marshal(indexCache{Format: indexFormat, Root: idx.Root, Fingerprint: fp, Templates: ts})
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	// Write a temp file and rename it into place, so a concurrent run never
	// reads a truncated cache.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nuclei-index-*.tmp")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(data)
	if cerr := tmp.Close(); werr != nil || cerr != nil {
		return
	}
	_ = os.Rename(tmp.Name(), path)
}
