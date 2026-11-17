package builder

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

const confineOverlayDoc = `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: confine-demo, summary: x }
base: { kind: image, image: nginx:1 }
service: { ports: [ { container: 80, protocol: http } ] }
states:
  vulnerable:
    overlay: [ { src: files/app.conf, dest: /etc/app.conf } ]
`

const buildDoc = `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: confine-build, summary: x }
base: { kind: build, context: src }
service: { ports: [ { container: 80, protocol: http } ] }
states:
  vulnerable:
    overlay: [ { src: files/app.conf, dest: app.conf } ]
`

// tmpl parses doc into a contract rooted at a fresh temp folder.
func tmpl(t *testing.T, doc string) *contract.Contract {
	t.Helper()
	c, err := contract.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	c.Folder = t.TempDir()
	if err := os.MkdirAll(filepath.Join(c.Folder, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	return c
}

func hostSecret(t *testing.T) (dir, file string) {
	t.Helper()
	dir = t.TempDir()
	file = filepath.Join(dir, "credentials")
	if err := os.WriteFile(file, []byte("HOST-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, file
}

func needSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
}

func noSecretInBuilds(t *testing.T, fe *enginetest.Fake) {
	t.Helper()
	for _, bl := range fe.Builds {
		for name, data := range bl.Files {
			if strings.Contains(data, "HOST-SECRET") {
				t.Fatalf("host file leaked into the build context as %s", name)
			}
		}
	}
}

func TestOverlayRefusesSymlinkOutOfTemplate(t *testing.T) {
	needSymlinks(t)
	c := tmpl(t, confineOverlayDoc)
	_, secret := hostSecret(t)
	os.Symlink(secret, filepath.Join(c.Folder, "files", "app.conf"))
	fe := enginetest.New()
	_, err := New(fe).Resolve(context.Background(), c, "vulnerable", Options{Pull: true})
	if !errors.Is(err, contract.ErrPathEscapes) {
		t.Fatalf("want ErrPathEscapes, got %v", err)
	}
	noSecretInBuilds(t, fe)
	if len(fe.Builds) != 0 {
		t.Fatal("nothing must be built")
	}
}

func TestOverlayRefusesTraversalBypassingParse(t *testing.T) {
	// Parse rejects these; the builder must refuse them too (defence in depth).
	_, secret := hostSecret(t)
	for _, src := range []string{"../../../../../../../../" + filepath.ToSlash(secret), secret} {
		c := tmpl(t, confineOverlayDoc)
		c.States["vulnerable"].Overlay[0].Src = src
		fe := enginetest.New()
		if _, err := New(fe).Resolve(context.Background(), c, "vulnerable", Options{Pull: true}); !errors.Is(err, contract.ErrPathEscapes) {
			t.Fatalf("%s: want ErrPathEscapes, got %v", src, err)
		}
		noSecretInBuilds(t, fe)
	}
}

func TestOverlaySymlinkInsideTemplateIsAllowed(t *testing.T) {
	needSymlinks(t)
	c := tmpl(t, confineOverlayDoc)
	os.MkdirAll(filepath.Join(c.Folder, "files", "common"), 0o755)
	os.WriteFile(filepath.Join(c.Folder, "files", "common", "app.conf"), []byte("shared"), 0o644)
	os.Symlink(filepath.Join("common", "app.conf"), filepath.Join(c.Folder, "files", "app.conf"))
	fe := enginetest.New()
	if _, err := New(fe).Resolve(context.Background(), c, "vulnerable", Options{Pull: true}); err != nil {
		t.Fatal(err)
	}
	if got := fe.Builds[0].Files["overlay_0_app.conf"]; got != "shared" {
		t.Fatalf("overlay content %q", got)
	}
}

func TestBuildContextConfined(t *testing.T) {
	needSymlinks(t)
	outside, _ := hostSecret(t)
	os.WriteFile(filepath.Join(outside, "Dockerfile"), []byte("FROM scratch\n"), 0o644)

	// context reached through a symlinked parent directory -> refused
	c := tmpl(t, strings.Replace(buildDoc, "context: src", "context: lnk/ctx", 1))
	os.MkdirAll(filepath.Join(outside, "ctx"), 0o755)
	os.WriteFile(filepath.Join(outside, "ctx", "Dockerfile"), []byte("FROM scratch\n"), 0o644)
	os.WriteFile(filepath.Join(outside, "ctx", "leak"), []byte("HOST-SECRET"), 0o644)
	os.Symlink(outside, filepath.Join(c.Folder, "lnk"))
	fe := enginetest.New()
	if _, err := New(fe).Resolve(context.Background(), c, "vulnerable", Options{}); !errors.Is(err, contract.ErrPathEscapes) {
		t.Fatalf("symlinked context: want ErrPathEscapes, got %v", err)
	}
	noSecretInBuilds(t, fe)

	// a real context: symlinks inside it travel as symlinks (resolved by the
	// daemon inside the context), never followed into the tar
	c = tmpl(t, buildDoc)
	src := filepath.Join(c.Folder, "src")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "Dockerfile"), []byte("FROM scratch\n"), 0o644)
	os.WriteFile(filepath.Join(c.Folder, "files", "app.conf"), []byte("cfg"), 0o644)
	os.Symlink(filepath.Join(outside, "credentials"), filepath.Join(src, "creds"))
	os.Symlink(outside, filepath.Join(src, "hostdir"))
	fe = enginetest.New()
	if _, err := New(fe).Resolve(context.Background(), c, "vulnerable", Options{}); err != nil {
		t.Fatal(err)
	}
	noSecretInBuilds(t, fe)
	files := fe.Builds[0].Files
	if files["app.conf"] != "cfg" || files["Dockerfile"] == "" {
		t.Fatalf("context: %v", keys(files))
	}
	links := fe.Builds[0].Links
	if links["creds"] != filepath.ToSlash(filepath.Join(outside, "credentials")) || links["hostdir"] != filepath.ToSlash(outside) {
		t.Fatalf("symlinks must be carried as links: %v", links)
	}
	for name, body := range files {
		if (name == "creds" || name == "hostdir") && body != "" || strings.HasPrefix(name, "hostdir/") {
			t.Fatalf("symlink %s must not be followed into the context", name)
		}
	}

	// a patch symlinked out of the folder is refused
	c.States["vulnerable"].Patch = "files/fix.patch"
	os.Symlink(filepath.Join(outside, "credentials"), filepath.Join(c.Folder, "files", "fix.patch"))
	if _, err := New(enginetest.New()).Resolve(context.Background(), c, "vulnerable", Options{}); !errors.Is(err, contract.ErrPathEscapes) {
		t.Fatalf("symlinked patch: want ErrPathEscapes, got %v", err)
	}
}

func TestOverlayDockerfileRejectsInjection(t *testing.T) {
	bad := []struct {
		name string
		ov   []overlayEntry
		env  map[string]string
	}{
		{"dest newline", []overlayEntry{{local: "f", dest: "/x\nRUN id"}}, nil},
		{"dest space", []overlayEntry{{local: "f", dest: "/x /y"}}, nil},
		{"dest shell", []overlayEntry{{local: "f", dest: "/x;id"}}, nil},
		{"dest relative", []overlayEntry{{local: "f", dest: "x"}}, nil},
		{"dest ..", []overlayEntry{{local: "f", dest: "/a/../../x"}}, nil},
		{"env value newline", nil, map[string]string{"A": "x\nRUN id"}},
		{"env value cr", nil, map[string]string{"A": "x\rRUN id"}},
		{"env key newline", nil, map[string]string{"A\nRUN id": "x"}},
		{"env key space", nil, map[string]string{"A B": "x"}},
	}
	for _, tc := range bad {
		if df, err := overlayDockerfile("img:1", tc.ov, tc.env, '\\'); err == nil {
			t.Errorf("%s: expected an error, got:\n%s", tc.name, df)
		}
	}
}

// The overlay mode goes into the build-context tar header (not a RUN chmod
// line); the builder still re-checks it, so a contract that bypassed Parse
// cannot set setuid/sticky bits or a file type, and a symlink escape is
// refused whether or not the overlay sets a mode.
func TestOverlayModeRechecked(t *testing.T) {
	for _, bad := range []string{"0644 /; id", "4755", "04755", "0o755", "755", "-1", "0999"} {
		c := tmpl(t, confineOverlayDoc)
		os.WriteFile(filepath.Join(c.Folder, "files", "app.conf"), []byte("cfg"), 0o644)
		c.States["vulnerable"].Overlay[0].Mode = bad
		fe := enginetest.New()
		if _, err := New(fe).Resolve(context.Background(), c, "vulnerable", Options{Pull: true}); err == nil {
			t.Errorf("mode %q: expected an error", bad)
		}
		if len(fe.Builds) != 0 {
			t.Errorf("mode %q: nothing must be built", bad)
		}
	}
	for _, good := range []struct {
		mode string
		want int64
	}{{"", 0o644}, {"0755", 0o755}, {"0600", 0o600}, {"0000", 0o644}} {
		if m, err := modeOf(good.mode); err != nil || m != good.want {
			t.Errorf("modeOf(%q) = %o, %v; want %o", good.mode, m, err, good.want)
		}
	}

	needSymlinks(t)
	_, secret := hostSecret(t)
	for _, doc := range []string{confineOverlayDoc, buildDoc} {
		c := tmpl(t, doc)
		os.MkdirAll(filepath.Join(c.Folder, "src"), 0o755)
		os.WriteFile(filepath.Join(c.Folder, "src", "Dockerfile"), []byte("FROM scratch\n"), 0o644)
		c.States["vulnerable"].Overlay[0].Mode = "0755"
		os.Symlink(secret, filepath.Join(c.Folder, "files", "app.conf"))
		fe := enginetest.New()
		if _, err := New(fe).Resolve(context.Background(), c, "vulnerable", Options{Pull: true}); !errors.Is(err, contract.ErrPathEscapes) {
			t.Fatalf("mode overlay through an escaping symlink: want ErrPathEscapes, got %v", err)
		}
		noSecretInBuilds(t, fe)
	}
}

func TestDockerfileQuoteEscapesDollar(t *testing.T) {
	df, err := overlayDockerfile("img:1", nil, map[string]string{
		"PW": "pa$word", "B": `a\b`, "C": "it's", "D": "plain", "E": "${HOME}",
	}, '\\')
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ENV PW=\"pa\\$word\"\n",
		"ENV B=\"a\\\\b\"\n",
		"ENV C=\"it's\"\n",
		"ENV D=plain\n",
		"ENV E=\"\\${HOME}\"\n",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("missing %q in:\n%s", want, df)
		}
	}
	// a Dockerfile declaring "# escape=`" gets backtick escapes
	if got := dockerfileQuote("pa$w`d", '`'); got != "\"pa`$w``d\"" {
		t.Fatalf("backtick escape: %s", got)
	}
	if escapeToken([]byte("# syntax=docker/dockerfile:1\n# escape=`\nFROM x\n")) != '`' {
		t.Fatal("escape directive not detected")
	}
	if escapeToken([]byte("FROM x\n# escape=`\n")) != '\\' {
		t.Fatal("a directive after an instruction is a comment")
	}
}

func TestBakeEnvHonoursEscapeDirective(t *testing.T) {
	mc := newBuildContext("")
	mc.add("Dockerfile", []byte("# escape=`\nFROM scratch\n"), 0o644)
	if err := bakeEnv(mc, "Dockerfile", map[string]string{"PW": "pa$word"}); err != nil {
		t.Fatal(err)
	}
	if df := string(mc.files["Dockerfile"].data); !strings.HasSuffix(df, "ENV PW=\"pa`$word\"\n") {
		t.Fatalf("got:\n%s", df)
	}
	if err := bakeEnv(mc, "Dockerfile", map[string]string{"X": "a\nRUN id"}); err == nil {
		t.Fatal("newline in a baked env value must be refused")
	}
}
