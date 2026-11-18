package builder

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
}

type entry struct {
	typ  byte
	body string
	link string
}

func readTar(t *testing.T, r io.Reader) map[string]entry {
	t.Helper()
	got := map[string]entry{}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return got
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		got[h.Name] = entry{typ: h.Typeflag, body: string(b), link: h.Linkname}
	}
}

// TestBuildContextTree checks what the streamed context carries (#47 item 7):
// symlinks as symlinks (they used to be dropped), .dockerignore honoured but
// never for the Dockerfile or .dockerignore itself, .git left out, and
// generated files replacing tree files of the same name.
func TestBuildContextTree(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM scratch\n")
	write(t, root, ".dockerignore", "# comment\n*.log\n!keep.log\nsecret\nDockerfile\n.dockerignore\n**/*.tmp\n")
	write(t, root, "app/main.py", "print(1)\n")
	write(t, root, "app/cache/x.tmp", "tmp")
	write(t, root, "debug.log", "noise")
	write(t, root, "keep.log", "kept")
	write(t, root, "secret/key", "k")
	write(t, root, ".git/config", "[core]")
	write(t, root, "app.py", "original")
	symlink(t, "app/main.py", filepath.Join(root, "main.py"))
	symlink(t, "/etc/passwd", filepath.Join(root, "abs-link"))

	bc := newBuildContext(root)
	bc.add("app.py", []byte("generated"), 0o755)
	s := bc.stream("Dockerfile")
	got := readTar(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var names []string
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	want := []string{".dockerignore", "Dockerfile", "abs-link", "app.py", "app/", "app/cache/", "app/main.py", "keep.log", "main.py"}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatalf("context:\n got  %v\n want %v", names, want)
	}
	if e := got["main.py"]; e.typ != tar.TypeSymlink || e.link != "app/main.py" {
		t.Fatalf("relative symlink: %+v", e)
	}
	// Carried as a link for the daemon to resolve inside the context; the
	// host file it names is never read.
	if e := got["abs-link"]; e.typ != tar.TypeSymlink || e.link != "/etc/passwd" || e.body != "" {
		t.Fatalf("absolute symlink: %+v", e)
	}
	if got["app.py"].body != "generated" {
		t.Fatalf("generated file must replace the tree file: %+v", got["app.py"])
	}
}

func TestBuildContextCloseWithoutReading(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM scratch\n")
	write(t, root, "big", strings.Repeat("x", 1<<20))
	s := newBuildContext(root).stream("Dockerfile")
	if _, err := s.Read(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	// The daemon gave up early: Close must stop the writer, not hang.
	if err := s.Close(); err != nil {
		t.Fatalf("close after a partial read: %v", err)
	}
}

func TestBuildContextErrorReachesBuild(t *testing.T) {
	root := t.TempDir()
	write(t, root, "ctx/Dockerfile", "FROM scratch\n")
	write(t, root, "ctx/.dockerignore", "[unterminated\n")
	c := &contract.Contract{Folder: root, Base: contract.Base{Kind: contract.BaseBuild, Context: "ctx"}}
	st := &contract.State{Name: "vulnerable"}
	fe := enginetest.New()
	err := New(fe).buildLocal(context.Background(), c, st, "t:1", Options{})
	if err == nil || !strings.Contains(err.Error(), ".dockerignore line 1") {
		t.Fatalf("want the .dockerignore error, got %v", err)
	}
}

func TestBakeEnvRefusesSymlinkedDockerfile(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, outside, "Dockerfile", "FROM scratch\n")
	symlink(t, filepath.Join(outside, "Dockerfile"), filepath.Join(root, "Dockerfile"))
	err := bakeEnv(newBuildContext(root), "Dockerfile", map[string]string{"A": "b"})
	if !errors.Is(err, contract.ErrPathEscapes) {
		t.Fatalf("a Dockerfile symlinked out of the context must not be read through: %v", err)
	}
	// Nor through a symlinked parent directory.
	symlink(t, outside, filepath.Join(root, "out"))
	err = bakeEnv(newBuildContext(root), "out/Dockerfile", map[string]string{"A": "b"})
	if !errors.Is(err, contract.ErrPathEscapes) {
		t.Fatalf("a Dockerfile under a directory symlinked out of the context must not be read: %v", err)
	}
	write(t, root, "sub/Dockerfile", "FROM scratch\n")
	bc := newBuildContext(root)
	if err := bakeEnv(bc, "sub/Dockerfile", map[string]string{"A": "b"}); err != nil {
		t.Fatal(err)
	}
	if df := string(bc.files["sub/Dockerfile"].data); df != "FROM scratch\nENV A=b\n" {
		t.Fatalf("baked: %q", df)
	}
}

// A Dockerfile symlinked to another file inside the context is accepted by
// validate and by the daemon, so baking environment into it must work too
// (it used to fail with "is a symlink" as soon as a state set environment).
func TestBakeEnvFollowsInContextSymlink(t *testing.T) {
	root := t.TempDir()
	write(t, root, "docker/Dockerfile.prod", "FROM scratch\n")
	symlink(t, "docker/Dockerfile.prod", filepath.Join(root, "Dockerfile"))
	write(t, root, "real/Dockerfile", "FROM busybox\n")
	symlink(t, "real", filepath.Join(root, "alias"))
	for name, want := range map[string]string{
		"Dockerfile":       "FROM scratch\nENV A=b\n",
		"alias/Dockerfile": "FROM busybox\nENV A=b\n",
	} {
		bc := newBuildContext(root)
		if err := bakeEnv(bc, name, map[string]string{"A": "b"}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if df := string(bc.files[name].data); df != want {
			t.Fatalf("%s baked: %q", name, df)
		}
	}
}

func TestCopyTreeKeepsSymlinks(t *testing.T) {
	src := t.TempDir()
	write(t, src, "a.txt", "a")
	symlink(t, "a.txt", filepath.Join(src, "l"))
	dst := filepath.Join(t.TempDir(), "ctx")
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	if link, err := os.Readlink(filepath.Join(dst, "l")); err != nil || link != "a.txt" {
		t.Fatalf("symlink not copied: %q %v", link, err)
	}
}

func TestDockerignorePatterns(t *testing.T) {
	cases := []struct {
		patterns string
		path     string
		excluded bool
	}{
		{"*.log", "a.log", true},
		{"*.log", "dir/a.log", false}, // * does not cross directories
		{"**/*.log", "dir/sub/a.log", true},
		{"**/*.log", "a.log", true},
		{"vendor", "vendor/a/b.go", true}, // a parent match excludes children
		{"/vendor/", "vendor/x", true},
		{"a?c", "abc", true},
		{"a?c", "a/c", false},
		{"[a-c].txt", "b.txt", true},
		{"[!a-c].txt", "b.txt", false},
		{"docs/**", "docs/x/y.md", true},
		{"docs/**", "docsx", false},
		{"*\n!keep", "keep", false},
		{"*\n!keep", "other", true},
		{"!keep\n*", "keep", true}, // the last matching pattern wins
		{".", "anything", true},
	}
	if runtime.GOOS != "windows" {
		// "\\" escapes only off Windows; there it is a path separator, as in Docker.
		cases = append(cases, []struct {
			patterns string
			path     string
			excluded bool
		}{{"x\\*y", "x*y", true}, {"x\\*y", "xay", false}}...)
	} else {
		cases = append(cases, struct {
			patterns string
			path     string
			excluded bool
		}{"dir\\*.log", "dir/a.log", true})
	}
	for _, tc := range cases {
		d, err := parseDockerignore([]byte(tc.patterns))
		if err != nil {
			t.Fatalf("%q: %v", tc.patterns, err)
		}
		if got := d.excludes(tc.path); got != tc.excluded {
			t.Errorf("patterns %q, path %q: excluded=%v, want %v", tc.patterns, tc.path, got, tc.excluded)
		}
	}
}
