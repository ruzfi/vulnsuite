package builder

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
