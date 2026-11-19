package contract

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withVulnerable inserts YAML lines (indented 4 spaces) into the vulnerable state.
func withVulnerable(doc, lines string) string {
	return strings.Replace(doc, "  vulnerable:\n", "  vulnerable:\n"+lines, 1)
}

const buildBase = `base:
  kind: build
  context: src
  dockerfile: Dockerfile
`

// asBuild swaps doc's base for a build base, dropping the patched state's
// image override, which only an image base allows.
func asBuild(doc string) string {
	i := strings.Index(doc, "base:\n")
	j := strings.Index(doc, "service:\n")
	return doc[:i] + buildBase + strings.Replace(doc[j:], "    image: httpd:2.4.51\n", "", 1)
}

func TestParseRejectsEscapingPaths(t *testing.T) {
	cases := map[string]string{
		"overlay src ..":                      withVulnerable(minimal, "    overlay: [ { src: ../../../../.ssh/id_rsa, dest: /x } ]\n"),
		"overlay src inner ..":                withVulnerable(minimal, "    overlay: [ { src: files/../../x, dest: /x } ]\n"),
		"overlay src inner .. staying inside": withVulnerable(minimal, "    overlay: [ { src: files/a/../b, dest: /etc/x } ]\n"),
		"overlay src absolute":                withVulnerable(minimal, "    overlay: [ { src: /etc/passwd, dest: /x } ]\n"),
		"overlay src backslash":               withVulnerable(minimal, "    overlay: [ { src: '..\\..\\x', dest: /x } ]\n"),
		"overlay src drive":                   withVulnerable(minimal, "    overlay: [ { src: 'C:/Windows/win.ini', dest: /x } ]\n"),
		"overlay src control":                 withVulnerable(minimal, "    overlay: [ { src: \"files/a\\nb\", dest: /x } ]\n"),
		"patch ..":                            withVulnerable(asBuild(minimal), "    patch: ../evil.patch\n"),
		"patch absolute":                      withVulnerable(asBuild(minimal), "    patch: /tmp/evil.patch\n"),
		"context ..":                          strings.Replace(asBuild(minimal), "context: src", "context: ../..", 1),
		"context absolute":                    strings.Replace(asBuild(minimal), "context: src", "context: /etc", 1),
		"dockerfile ..":                       strings.Replace(asBuild(minimal), "dockerfile: Dockerfile", "dockerfile: ../../Dockerfile", 1),
		"dockerfile absolute":                 strings.Replace(asBuild(minimal), "dockerfile: Dockerfile", "dockerfile: /etc/Dockerfile", 1),
		"dest relative on image":              withVulnerable(minimal, "    overlay: [ { src: files/x, dest: etc/x } ]\n"),
		"dest newline":                        withVulnerable(minimal, "    overlay: [ { src: files/x, dest: \"/x\\nRUN id\" } ]\n"),
		"dest carriage return":                withVulnerable(minimal, "    overlay: [ { src: files/x, dest: \"/x\\rRUN id\" } ]\n"),
		"dest space":                          withVulnerable(minimal, "    overlay: [ { src: files/x, dest: \"/a b\" } ]\n"),
		"dest dollar":                         withVulnerable(minimal, "    overlay: [ { src: files/x, dest: \"/a$HOME\" } ]\n"),
		"dest shell":                          withVulnerable(minimal, "    overlay: [ { src: files/x, dest: \"/a;id\" } ]\n"),
		"dest ..":                             withVulnerable(minimal, "    overlay: [ { src: files/x, dest: /etc/../../x } ]\n"),
		"dest root":                           withVulnerable(minimal, "    overlay: [ { src: files/x, dest: / } ]\n"),
		"dest .. on build":                    withVulnerable(asBuild(minimal), "    overlay: [ { src: files/x, dest: ../x } ]\n"),
		"env value newline":                   withVulnerable(minimal, "    environment: { A: \"x\\nRUN id\" }\n"),
		"env value carriage ret":              withVulnerable(minimal, "    environment: { A: \"x\\rRUN id\" }\n"),
		"env key newline":                     withVulnerable(minimal, "    environment: { \"A\\nRUN id\": x }\n"),
		"env key space":                       withVulnerable(minimal, "    environment: { \"A B\": x }\n"),
		"env key equals":                      withVulnerable(minimal, "    environment: { \"A=B\": x }\n"),
	}
	for name, doc := range cases {
		_, err := Parse([]byte(doc))
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		var se *SchemaError
		if !errors.As(err, &se) || !strings.Contains(se.Loc, wantLoc(name)) {
			t.Errorf("%s: rejected for the wrong reason: %v", name, err)
		}
	}
}

// wantLoc maps a case name to the schema location its error must point at.
func wantLoc(name string) string {
	for _, k := range []string{"src", "patch", "context", "dockerfile", "dest", "env"} {
		if strings.Contains(name, k) {
			if k == "env" {
				return "environment"
			}
			return k
		}
	}
	return name
}

func TestParseAcceptsLocalPaths(t *testing.T) {
	cases := map[string]string{
		"overlay in files":       withVulnerable(minimal, "    overlay: [ { src: files/vuln/httpd.conf, dest: /usr/local/apache2/conf/httpd.conf, mode: \"0644\" } ]\n"),
		"dotted dest":            withVulnerable(minimal, "    overlay: [ { src: files/x, dest: /usr/share/nginx/html/.git/config } ]\n"),
		"relative dest on build": withVulnerable(asBuild(minimal), "    overlay: [ { src: files/x, dest: Dockerfile }, { src: files/y, dest: VARIANT } ]\n"),
		"patch on build":         withVulnerable(asBuild(minimal), "    patch: patches/fix.patch\n"),
		"env with $ and quotes":  withVulnerable(minimal, "    environment: { PW: \"pa$word\", Q: \"a \\\"b\\\" c\", DOT.KEY: v }\n"),
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestConfinedPath(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "files", "common"), 0o755))
	must(os.WriteFile(filepath.Join(root, "files", "common", "a.conf"), []byte("in"), 0o644))
	must(os.WriteFile(filepath.Join(outside, "secret"), []byte("host"), 0o600))

	// a plain file inside resolves
	p, err := ConfinedPath(root, "files/common/a.conf")
	if err != nil || !strings.HasSuffix(p, "a.conf") {
		t.Fatalf("inside: %q %v", p, err)
	}
	// lexical escapes are refused without touching the disk
	for _, rel := range []string{"../x", "files/../../x", "/etc/passwd", `..\x`, "C:/x", ""} {
		if _, err := ConfinedPath(root, rel); !errors.Is(err, ErrPathEscapes) {
			t.Errorf("%q: want ErrPathEscapes, got %v", rel, err)
		}
	}
	// missing files report the os error, not an escape
	if _, err := ConfinedPath(root, "files/nope"); err == nil || errors.Is(err, ErrPathEscapes) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}

	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	// a symlink to a host file is refused
	must(os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "files", "link.conf")))
	if _, err := ConfinedPath(root, "files/link.conf"); !errors.Is(err, ErrPathEscapes) {
		t.Fatalf("symlink out: %v", err)
	}
	// a symlinked directory leading outside is refused too
	must(os.Symlink(outside, filepath.Join(root, "files", "dir")))
	if _, err := ConfinedPath(root, "files/dir/secret"); !errors.Is(err, ErrPathEscapes) {
		t.Fatalf("symlinked dir out: %v", err)
	}
	// a symlink that stays inside the folder is fine and resolves to its target
	must(os.Symlink(filepath.Join("common", "a.conf"), filepath.Join(root, "files", "alias.conf")))
	p, err = ConfinedPath(root, "files/alias.conf")
	if err != nil {
		t.Fatalf("symlink in: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "in" {
		t.Fatalf("symlink in resolved to %s", p)
	}
	// the template folder itself may sit behind a symlink
	linkRoot := filepath.Join(t.TempDir(), "tpl")
	must(os.Symlink(root, linkRoot))
	if _, err := ConfinedPath(linkRoot, "files/common/a.conf"); err != nil {
		t.Fatalf("symlinked root: %v", err)
	}
}

func TestContentHashIgnoresEscapingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	// Every overlay shape the hash covers: plain, with a mode (set in the tar
	// header), and on top of a state image override.
	for _, lines := range []string{
		"    overlay: [ { src: files/link.conf, dest: /x } ]\n",
		"    overlay: [ { src: files/link.conf, dest: /x, mode: \"0755\" } ]\n",
		"    image: nginx:1.27\n    overlay: [ { src: files/link.conf, dest: /x, mode: \"0600\" } ]\n",
	} {
		c, err := Parse([]byte(withVulnerable(minimal, lines)))
		if err != nil {
			t.Fatal(err)
		}
		c.Folder = t.TempDir()
		os.MkdirAll(filepath.Join(c.Folder, "files"), 0o755)
		missing := c.ContentHash("vulnerable")
		secret := filepath.Join(t.TempDir(), "secret")
		os.WriteFile(secret, []byte("host secret"), 0o600)
		os.Symlink(secret, filepath.Join(c.Folder, "files", "link.conf"))
		if got := c.ContentHash("vulnerable"); got != missing {
			t.Fatalf("%q: an escaping symlink's target must not feed the content hash", lines)
		}
		// A symlink that stays inside the folder is hashed by its target.
		os.Remove(filepath.Join(c.Folder, "files", "link.conf"))
		os.WriteFile(filepath.Join(c.Folder, "files", "real.conf"), []byte("inside"), 0o644)
		os.Symlink("real.conf", filepath.Join(c.Folder, "files", "link.conf"))
		if got := c.ContentHash("vulnerable"); got == missing {
			t.Fatalf("%q: an in-folder symlink must be hashed", lines)
		}
	}
}
