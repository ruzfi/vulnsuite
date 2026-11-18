package builder

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// buildContext is a Docker build context: an optional directory tree plus a
// few generated files (overlays, a Dockerfile with baked env) that are added
// on top of it, replacing any tree file of the same name. It is written out
// as a tar stream on demand, so a large tree is never held in memory.
type buildContext struct {
	root  string             // tree to include ("" = none)
	files map[string]memFile // generated entries, keyed by slash path
}

type memFile struct {
	data []byte
	mode int64
}

func newBuildContext(root string) *buildContext {
	return &buildContext{root: root, files: map[string]memFile{}}
}

func (m *buildContext) add(name string, data []byte, mode int64) {
	if mode == 0 {
		mode = 0o644
	}
	m.files[filepath.ToSlash(name)] = memFile{data: data, mode: mode}
}

// readFile returns a context file's content: a generated entry, or a regular
// file of the tree (never through a symlink, which may point anywhere).
func (m *buildContext) readFile(name string) (memFile, bool, error) {
	name = filepath.ToSlash(filepath.Clean(name))
	if f, ok := m.files[name]; ok {
		return f, true, nil
	}
	if m.root == "" || name == ".." || strings.HasPrefix(name, "../") || path.IsAbs(name) {
		return memFile{}, false, nil
	}
	p := m.root
	for _, part := range strings.Split(name, "/") {
		p = filepath.Join(p, part)
		info, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			return memFile{}, false, nil
		}
		if err != nil {
			return memFile{}, false, err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return memFile{}, false, fmt.Errorf("%s: is a symlink", name)
		}
	}
	info, err := os.Stat(p)
	if err != nil {
		return memFile{}, false, err
	}
	if !info.Mode().IsRegular() {
		return memFile{}, false, fmt.Errorf("%s is not a regular file", name)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return memFile{}, false, err
	}
	return memFile{data: data, mode: int64(info.Mode().Perm())}, true, nil
}

// stream writes the context as a tar through a pipe. dockerfile is the
// Dockerfile's path in the context, which -- like .dockerignore -- is always
// sent even when .dockerignore excludes it (as the Docker CLI does). Close the
// returned stream once the build is done so the writer goroutine stops even
// when the daemon did not read it to the end.
func (m *buildContext) stream(dockerfile string) *contextStream {
	pr, pw := io.Pipe()
	cs := &contextStream{pr: pr, done: make(chan struct{})}
	go func() {
		defer close(cs.done)
		err := m.writeTar(pw, dockerfile)
		cs.err = err
		pw.CloseWithError(err)
	}()
	return cs
}

type contextStream struct {
	pr   *io.PipeReader
	done chan struct{}
	err  error // the writer's error, valid once done is closed
}

func (s *contextStream) Read(p []byte) (int, error) { return s.pr.Read(p) }

// Close stops the writer and returns the error it hit, if any (an error from
// reading the tree, which explains a failed build better than the daemon's
// "unexpected EOF").
func (s *contextStream) Close() error {
	s.pr.CloseWithError(errContextClosed)
	<-s.done
	if errors.Is(s.err, errContextClosed) {
		return nil
	}
	return s.err
}

var errContextClosed = errors.New("build context closed")

func (m *buildContext) writeTar(w io.Writer, dockerfile string) error {
	tw := tar.NewWriter(w)
	if m.root != "" {
		ign, err := readDockerignore(m.root)
		if err != nil {
			return err
		}
		keep := map[string]bool{".dockerignore": true, filepath.ToSlash(filepath.Clean(dockerfile)): true}
		if err := m.walkTree(tw, ign, keep); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(m.files))
	for n := range m.files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := m.files[n]
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: f.mode, Size: int64(len(f.data)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tw.Write(f.data); err != nil {
			return err
		}
	}
	return tw.Close()
}

// walkTree writes the tree's directories, regular files and symlinks (as
// symlinks: the daemon resolves them inside the context, never on the host).
// .git, names .dockerignore excludes, and names a generated file replaces are
// left out.
func (m *buildContext) walkTree(tw *tar.Writer, ign *dockerignore, keep map[string]bool) error {
	root := m.root
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if d.IsDir() && name == ".git" {
			return filepath.SkipDir
		}
		if !keep[name] && ign.excludes(name) {
			// An excluded directory is still walked when it holds a kept
			// file (the Docker CLI adds "!<dockerfile>" to the excludes, so
			// "docker" in .dockerignore does not drop docker/Dockerfile).
			if d.IsDir() && !ign.hasExceptions && !holdsKept(name, keep) {
				return filepath.SkipDir
			}
			return nil
		}
		if _, generated := m.files[name]; generated {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// No ModTime: the context (and so the build cache) depends on content only.
		hdr := &tar.Header{Name: name, Mode: int64(info.Mode().Perm())}
		switch {
		case info.IsDir():
			hdr.Typeflag, hdr.Name = tar.TypeDir, name+"/"
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			hdr.Typeflag, hdr.Linkname, hdr.Mode = tar.TypeSymlink, filepath.ToSlash(target), 0o777
		case info.Mode().IsRegular():
			hdr.Typeflag, hdr.Size = tar.TypeReg, info.Size()
		default:
			return nil // devices, sockets, pipes are not carried
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.CopyN(tw, f, hdr.Size)
		return err
	})
}

// holdsKept reports whether dir is a parent directory of a kept path.
func holdsKept(dir string, keep map[string]bool) bool {
	for k := range keep {
		if strings.HasPrefix(k, dir+"/") {
			return true
		}
	}
	return false
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
