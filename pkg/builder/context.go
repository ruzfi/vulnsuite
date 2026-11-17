package builder

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/contract"
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
// mounts and the result is a portable image. esc is the Dockerfile escape
// character in effect where the lines end up.
//
// Every value is template-controlled, so nothing may break out of its line:
// dest is re-checked (a plain path, no whitespace or shell metacharacters),
// env keys/values may not contain control characters, and values are quoted
// with $ escaped so they are baked literally.
func overlayDockerfile(baseRef string, overlays []overlayEntry, env map[string]string, esc rune) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "FROM %s\n", baseRef)
	for _, o := range overlays {
		if err := contract.CheckOverlayDest(o.dest, true); err != nil {
			return "", fmt.Errorf("overlay dest %q: %w", o.dest, err)
		}
		// The file's mode is set in the build-context tar header and COPY
		// keeps it, so no RUN chmod (which fails on non-root or shell-less bases).
		fmt.Fprintf(&b, "COPY %s %s\n", o.local, o.dest)
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := contract.CheckEnv(k, env[k]); err != nil {
			return "", fmt.Errorf("environment: %w", err)
		}
		fmt.Fprintf(&b, "ENV %s=%s\n", k, dockerfileQuote(env[k], esc))
	}
	return b.String(), nil
}

var modeRe = regexp.MustCompile(`^0[0-7]{3}$`)

type overlayEntry struct {
	local string // file name inside the build context
	dest  string // absolute path inside the image
}

// plainValueRe is an ENV value that needs no quoting.
var plainValueRe = regexp.MustCompile(`^[A-Za-z0-9_./:@%+,=-]*$`)

// dockerfileQuote renders an ENV value so the Dockerfile parser reads it back
// literally: anything beyond a plain token is double-quoted, and the escape
// character, '"' and '$' (variable expansion) are escaped with esc.
func dockerfileQuote(v string, esc rune) string {
	if plainValueRe.MatchString(v) && v != "" {
		return v
	}
	e := string(esc)
	return `"` + strings.NewReplacer(e, e+e, `"`, e+`"`, `$`, e+`$`).Replace(v) + `"`
}

// directiveRe matches a Dockerfile parser directive line ("# escape=`").
var directiveRe = regexp.MustCompile(`^#\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(\S+)\s*$`)

// escapeToken returns the escape character a Dockerfile declares with the
// "# escape=" parser directive, or the default backslash.
func escapeToken(dockerfile []byte) rune {
	for _, line := range strings.Split(string(dockerfile), "\n") {
		m := directiveRe.FindStringSubmatch(strings.TrimSpace(strings.TrimPrefix(line, "\ufeff")))
		if m == nil {
			break // directives only appear before any other line
		}
		if strings.EqualFold(m[1], "escape") && m[2] == "`" {
			return '`'
		}
	}
	return '\\'
}
