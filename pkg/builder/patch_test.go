package builder

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const flipPatch = "--- a/app.txt\n+++ b/app.txt\n@@ -1 +1 @@\n-vulnerable\n+patched\n"

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func writePatch(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fix.patch")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readString(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// applyPatch must apply a plain patch to a directory that is not a
// repository (a copied build context). It used to pass an absolute
// --directory, which git rejects for every path, and then fall back to a
// GNU-only patch flag that BSD patch (macOS) does not accept.
func TestApplyPatchPlainDirectory(t *testing.T) {
	needGit(t)
	dir := filepath.Join(t.TempDir(), "ctx")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "app.txt"), []byte("vulnerable\n"), 0o644)
	if err := (&Builder{}).applyPatch(context.Background(), dir, writePatch(t, flipPatch)); err != nil {
		t.Fatalf("applyPatch: %v", err)
	}
	if got := readString(t, filepath.Join(dir, "app.txt")); got != "patched\n" {
		t.Fatalf("app.txt = %q, want patched", got)
	}
}

// A copied context nested inside some other checkout (TMPDIR inside a repo)
// is still patched relative to itself, not to the enclosing repository.
func TestApplyPatchInsideEnclosingRepo(t *testing.T) {
	needGit(t)
	outer := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", outer).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	os.WriteFile(filepath.Join(outer, "app.txt"), []byte("vulnerable\n"), 0o644)
	dir := filepath.Join(outer, "tmp", "ctx")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "app.txt"), []byte("vulnerable\n"), 0o644)
	if err := (&Builder{}).applyPatch(context.Background(), dir, writePatch(t, flipPatch)); err != nil {
		t.Fatalf("applyPatch: %v", err)
	}
	if got := readString(t, filepath.Join(dir, "app.txt")); got != "patched\n" {
		t.Errorf("ctx/app.txt = %q, want patched", got)
	}
	if got := readString(t, filepath.Join(outer, "app.txt")); got != "vulnerable\n" {
		t.Errorf("enclosing repo's app.txt changed to %q", got)
	}
}

// A source base is a clone: the patch applies at its root.
func TestApplyPatchRepoRoot(t *testing.T) {
	needGit(t)
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	os.WriteFile(filepath.Join(dir, "app.txt"), []byte("vulnerable\n"), 0o644)
	if err := (&Builder{}).applyPatch(context.Background(), dir, writePatch(t, flipPatch)); err != nil {
		t.Fatalf("applyPatch: %v", err)
	}
	if got := readString(t, filepath.Join(dir, "app.txt")); got != "patched\n" {
		t.Fatalf("app.txt = %q, want patched", got)
	}
}

// A patch that writes through a symlink in the context must not modify the
// file the link points to outside the tree.
func TestApplyPatchRefusesWriteThroughSymlink(t *testing.T) {
	needGit(t)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "app.txt"), []byte("vulnerable\n"), 0o644)
	dir := filepath.Join(t.TempDir(), "ctx")
	os.MkdirAll(dir, 0o755)
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p := "--- a/link/app.txt\n+++ b/link/app.txt\n@@ -1 +1 @@\n-vulnerable\n+patched\n"
	err := (&Builder{}).applyPatch(context.Background(), dir, writePatch(t, p))
	if got := readString(t, filepath.Join(outside, "app.txt")); got != "vulnerable\n" {
		t.Fatalf("patch wrote through a symlink outside the tree (err=%v)", err)
	}
	if err == nil {
		t.Error("want an error for a patch through a symlink")
	}
}

// A patch that does not apply is reported, not silently ignored.
func TestApplyPatchMismatchFails(t *testing.T) {
	needGit(t)
	dir := filepath.Join(t.TempDir(), "ctx")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "app.txt"), []byte("something else\n"), 0o644)
	if err := (&Builder{}).applyPatch(context.Background(), dir, writePatch(t, flipPatch)); err == nil {
		t.Fatal("want an error for a patch that does not apply")
	}
}

// #147: the GNU patch fallback used --no-absolute-filenames, a cpio/tar
// option GNU patch rejects ("unrecognized option", exit 2), so it could never
// apply anything. The paths are absolute option values and "--" ends the
// options.
func TestPatchFallbackArgs(t *testing.T) {
	t.Chdir(t.TempDir())
	args := patchFallbackArgs("-ctx", "-fix.patch")
	if strings.Contains(strings.Join(args, " "), "no-absolute-filenames") {
		t.Fatalf("args carry a non-GNU-patch option: %v", args)
	}
	if args[len(args)-1] != "--" {
		t.Fatalf("args must end the options with --: %v", args)
	}
	for _, a := range args {
		v, ok := strings.CutPrefix(a, "--directory=")
		if !ok {
			v, ok = strings.CutPrefix(a, "--input=")
		}
		if ok && !filepath.IsAbs(v) {
			t.Errorf("%s: path not absolute", a)
		}
	}
}

// fuzzPatch needs fuzz to apply (its first context line no longer matches),
// so git apply refuses it and only the GNU patch fallback can apply it.
const fuzzPatch = "--- a/app.txt\n+++ b/app.txt\n@@ -1,7 +1,7 @@\n l1\n l2\n l3\n-vulnerable\n+patched\n l5\n l6\n l7\n"

// With GNU patch on PATH (Linux CI, the release images), a patch that needs
// fuzz falls back to it and applies.
func TestApplyPatchGNUFallbackAppliesWithFuzz(t *testing.T) {
	needGit(t)
	if !isGNUPatch(context.Background()) {
		t.Skip("GNU patch not on PATH")
	}
	dir := filepath.Join(t.TempDir(), "ctx")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "app.txt"), []byte("CHANGED\nl2\nl3\nvulnerable\nl5\nl6\n"), 0o644)
	if err := (&Builder{}).applyPatch(context.Background(), dir, writePatch(t, fuzzPatch)); err != nil {
		t.Fatalf("applyPatch: %v", err)
	}
	if got := readString(t, filepath.Join(dir, "app.txt")); got != "CHANGED\nl2\nl3\npatched\nl5\nl6\n" {
		t.Fatalf("app.txt = %q", got)
	}
}

// Without GNU patch (BSD patch on macOS), the same patch fails closed.
func TestApplyPatchFuzzWithoutGNUPatchFails(t *testing.T) {
	needGit(t)
	if isGNUPatch(context.Background()) {
		t.Skip("GNU patch on PATH")
	}
	dir := filepath.Join(t.TempDir(), "ctx")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "app.txt"), []byte("CHANGED\nl2\nl3\nvulnerable\nl5\nl6\n"), 0o644)
	if err := (&Builder{}).applyPatch(context.Background(), dir, writePatch(t, fuzzPatch)); err == nil {
		t.Fatal("want git's error when only a non-GNU patch is available")
	}
}

// A patch whose target escapes the tree through a symlink, or that creates a
// file there, leaves the outside untouched with the GNU fallback too.
func TestApplyPatchSymlinkCreateRefused(t *testing.T) {
	needGit(t)
	outside := t.TempDir()
	dir := filepath.Join(t.TempDir(), "ctx")
	os.MkdirAll(dir, 0o755)
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p := "--- /dev/null\n+++ b/link/new\n@@ -0,0 +1 @@\n+pwned\n"
	err := (&Builder{}).applyPatch(context.Background(), dir, writePatch(t, p))
	if _, serr := os.Lstat(filepath.Join(outside, "new")); serr == nil {
		t.Fatalf("patch created a file through a symlink outside the tree (err=%v)", err)
	}
}

// #147: source clones and checkouts force LF line endings, so a Windows git
// with core.autocrlf=true does not write scripts with CRLF.
func TestCheckoutSourceForcesLF(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake git")
	}
	bin := t.TempDir()
	log := filepath.Join(bin, "log")
	script := "#!/bin/sh\necho \"$*\" >> '" + log + "'\ncase \"$*\" in *' clone '*) for a; do last=$a; done; mkdir -p \"$last\";; esac\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "src")
	b := &Builder{Git: filepath.Join(bin, "git")}
	if err := b.checkoutSource(context.Background(), "https://example.invalid/r.git", "abc123", dst); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(readString(t, log)), "\n")
	if len(lines) != 2 {
		t.Fatalf("git calls: %q", lines)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "-c core.autocrlf=false -c core.eol=lf ") {
			t.Errorf("git %s: does not force LF", l)
		}
	}
	if !strings.Contains(lines[0], " clone ") || !strings.Contains(lines[1], " checkout ") {
		t.Errorf("git calls: %q", lines)
	}
}
