package builder

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// memContext is an in-memory build context, written out as a tar stream.
type memContext struct {
	files map[string]memFile
}

type memFile struct {
	data []byte
	mode int64
}

func newMemContext() *memContext { return &memContext{files: map[string]memFile{}} }

func (m *memContext) add(name string, data []byte, mode int64) {
	if mode == 0 {
		mode = 0o644
	}
	m.files[filepath.ToSlash(name)] = memFile{data: data, mode: mode}
}

// addTree copies a directory tree into the context under prefix.
func (m *memContext) addTree(root, prefix string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil // symlinks etc. are not carried into the context
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		m.add(filepath.Join(prefix, rel), data, int64(info.Mode().Perm()))
		return nil
	})
}

// tar renders the context as a tar stream.
func (m *memContext) tar() io.Reader {
	names := make([]string, 0, len(m.files))
	for n := range m.files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		f := m.files[n]
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: f.mode, Size: int64(len(f.data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(f.data)
	}
	_ = tw.Close()
	return &buf
}

// overlayDockerfile generates the tiny Dockerfile that bakes overlay files and
// environment into a prebuilt image, so the running container needs no volume
// mounts and the result is a portable image.
func overlayDockerfile(baseRef string, overlays []overlayEntry, env map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "FROM %s\n", baseRef)
	for _, o := range overlays {
		fmt.Fprintf(&b, "COPY %s %s\n", o.local, o.dest)
		if o.mode != "" {
			fmt.Fprintf(&b, "RUN chmod %s %s\n", o.mode, o.dest)
		}
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "ENV %s=%s\n", k, dockerfileQuote(env[k]))
	}
	return b.String()
}

type overlayEntry struct {
	local string // file name inside the build context
	dest  string // absolute path inside the image
	mode  string
}

func dockerfileQuote(v string) string {
	if strings.ContainsAny(v, " \t\"\\$") {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
	}
	return v
}
