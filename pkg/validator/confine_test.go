package validator

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPathEscapesTemplate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	v := &Validator{}
	c := parse(t, strings.Replace(base, "  patched:\n", "  patched:\n    overlay: [ { src: files/link.conf, dest: /etc/x } ]\n", 1))
	os.MkdirAll(filepath.Join(c.Folder, "files", "common"), 0o755)
	secret := filepath.Join(t.TempDir(), "credentials")
	os.WriteFile(secret, []byte("host"), 0o600)
	os.Symlink(secret, filepath.Join(c.Folder, "files", "link.conf"))
	r := rules(v.Check(c))
	if r["path-escapes-template"] != Error {
		t.Fatalf("path-escapes-template expected: %v", r)
	}
	if _, dup := r["missing-overlay"]; dup {
		t.Fatalf("an escaping path is not also reported missing: %v", r)
	}

	// a symlink that stays inside the template is fine
	os.Remove(filepath.Join(c.Folder, "files", "link.conf"))
	os.WriteFile(filepath.Join(c.Folder, "files", "common", "x"), []byte("1"), 0o644)
	os.Symlink(filepath.Join("common", "x"), filepath.Join(c.Folder, "files", "link.conf"))
	r = rules(v.Check(c))
	if _, bad := r["path-escapes-template"]; bad {
		t.Fatalf("in-folder symlink flagged: %v", r)
	}
	if _, bad := r["missing-overlay"]; bad {
		t.Fatalf("in-folder symlink reported missing: %v", r)
	}
}

func TestBuildContextEscapesTemplate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	doc := strings.Replace(base,
		"base: { kind: image, image: nginx:1, digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }",
		"base: { kind: build, context: src }", 1)
	c := parse(t, doc)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "Dockerfile"), []byte("FROM scratch\n"), 0o644)
	os.Symlink(outside, filepath.Join(c.Folder, "src"))
	r := rules((&Validator{}).Check(c))
	if r["path-escapes-template"] != Error {
		t.Fatalf("symlinked context: %v", r)
	}

	// a real context whose Dockerfile is a symlink out of it
	c = parse(t, doc)
	os.MkdirAll(filepath.Join(c.Folder, "src"), 0o755)
	os.Symlink(filepath.Join(outside, "Dockerfile"), filepath.Join(c.Folder, "src", "Dockerfile"))
	r = rules((&Validator{}).Check(c))
	if r["path-escapes-template"] != Error {
		t.Fatalf("symlinked dockerfile: %v", r)
	}
}
