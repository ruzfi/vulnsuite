//go:build unix

package builder

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The patched copy of a context must carry the source's permission bits
// (they end up in the context's tar headers), whatever the umask.
func TestCopyTreeKeepsPermissions(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	src := t.TempDir()
	write(t, src, "www/index.html", "x")
	write(t, src, "run.sh", "#!/bin/sh\n")
	write(t, src, "private", "p")
	for rel, mode := range map[string]os.FileMode{
		"www": 0o755, "www/index.html": 0o644, "run.sh": 0o755, "private": 0o600,
	} {
		if err := os.Chmod(filepath.Join(src, rel), mode); err != nil {
			t.Fatal(err)
		}
	}
	dst := filepath.Join(t.TempDir(), "ctx")
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]os.FileMode{
		"www": 0o755, "www/index.html": 0o644, "run.sh": 0o755, "private": 0o600,
	} {
		info, err := os.Stat(filepath.Join(dst, rel))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s: mode %v, want %v", rel, got, want)
		}
	}
}
