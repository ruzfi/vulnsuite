package templates

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// contractBody is a minimal contract, enough for HasTemplates to count it.
const contractBody = "apiVersion: vulnsuite/v1\nkind: Target\n"

// unzipBytes extracts an in-memory archive.
func unzipBytes(data []byte, dst string) error {
	_, err := unzipStripTop(bytes.NewReader(data), int64(len(data)), dst)
	return err
}

// setLimits lowers archiveLimits for one test; zero keeps a limit.
func setLimits(t *testing.T, download, extract int64, entries int) {
	t.Helper()
	orig := archiveLimits
	t.Cleanup(func() { archiveLimits = orig })
	if download > 0 {
		archiveLimits.download = download
	}
	if extract > 0 {
		archiveLimits.extract = extract
	}
	if entries > 0 {
		archiveLimits.entries = entries
	}
}

// installedDir is a templates directory installed by an earlier update.
func installedDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tpl")
	if err := os.MkdirAll(filepath.Join(dir, "web", "old"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, versionFile), []byte("old\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "web", "old", "contract.yaml"), []byte(contractBody), 0o644)
	return dir
}

// mustKeepOld checks an installedDir survived a failed update intact, with
// no temporary directory or archive left next to it.
func mustKeepOld(t *testing.T, dir string) {
	t.Helper()
	mustExist(t, filepath.Join(dir, "web", "old", "contract.yaml"))
	if b, _ := os.ReadFile(filepath.Join(dir, versionFile)); string(b) != "old\n" {
		t.Fatalf("version marker changed: %q", b)
	}
	if _, err := os.Lstat(filepath.Join(dir, "web", "x")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nothing from the rejected archive should be installed: %v", err)
	}
	if sib := siblings(t, dir); len(sib) != 0 {
		t.Fatalf("leftovers: %v", sib)
	}
}

func TestUpdateArchiveRejectsZipBomb(t *testing.T) {
	setLimits(t, 0, 64<<10, 0)
	zeros := strings.Repeat("\x00", 1<<20) // ~1 KiB deflated
	cases := map[string][]byte{
		"one large entry": makeZip(t,
			zipEntry{name: "vulnsuite-templates-main/web/x/contract.yaml", body: contractBody},
			zipEntry{name: "vulnsuite-templates-main/web/x/bomb.bin", body: zeros},
		),
		// Each entry is under the cap; only their total is over it.
		"many small entries": makeZip(t,
			zipEntry{name: "vulnsuite-templates-main/web/x/contract.yaml", body: contractBody},
			zipEntry{name: "vulnsuite-templates-main/a.bin", body: zeros[:40<<10]},
			zipEntry{name: "vulnsuite-templates-main/b.bin", body: zeros[:40<<10]},
		),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if len(data) > 64<<10 {
				t.Fatalf("fixture should be small compressed: %d bytes", len(data))
			}
			dir := installedDir(t)
			s := serveArchive(t, http.StatusOK, data)
			_, _, err := Update(context.Background(), opts(dir, s))
			if err == nil || !strings.Contains(err.Error(), "size limit") || !strings.Contains(err.Error(), "left unchanged") {
				t.Fatalf("err = %v", err)
			}
			mustKeepOld(t, dir)
		})
	}
}

func TestUpdateArchiveRejectsTooManyEntries(t *testing.T) {
	setLimits(t, 0, 0, 10)
	entries := []zipEntry{{name: "vulnsuite-templates-main/web/x/contract.yaml", body: contractBody}}
	for i := 0; i < 20; i++ {
		entries = append(entries, zipEntry{name: fmt.Sprintf("vulnsuite-templates-main/d%d/", i), mode: os.ModeDir | 0o755})
	}
	dir := installedDir(t)
	s := serveArchive(t, http.StatusOK, makeZip(t, entries...))
	_, _, err := Update(context.Background(), opts(dir, s))
	if err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("err = %v", err)
	}
	mustKeepOld(t, dir)
}

func TestUpdateArchiveRejectsOversizedDownload(t *testing.T) {
	setLimits(t, 4<<10, 0, 0)
	// Incompressible padding keeps the archive itself over the cap.
	pad := make([]byte, 16<<10)
	for i := range pad {
		pad[i] = byte(i*7919>>3) ^ byte(i>>5)
	}
	data := makeZip(t,
		zipEntry{name: "vulnsuite-templates-main/web/x/contract.yaml", body: contractBody},
		zipEntry{name: "vulnsuite-templates-main/pad.bin", body: string(pad)},
	)
	if len(data) <= 4<<10 {
		t.Fatalf("fixture too small: %d bytes", len(data))
	}
	// With a Content-Length, and streamed (chunked) without one.
	for _, chunked := range []bool{false, true} {
		dir := installedDir(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if chunked {
				w.(http.Flusher).Flush()
			}
			_, _ = w.Write(data)
		}))
		t.Cleanup(srv.Close)
		_, _, err := Update(context.Background(), UpdateOptions{Dir: dir, ArchiveBaseURL: srv.URL, HTTPClient: srv.Client()})
		if err == nil || !strings.Contains(err.Error(), "byte limit") {
			t.Fatalf("chunked=%v: err = %v", chunked, err)
		}
		mustKeepOld(t, dir)
	}
}

func TestUpdateArchiveWithoutTemplatesKeepsOld(t *testing.T) {
	// A wrong -repo: a valid archive, but of an unrelated repository.
	data := makeZip(t,
		zipEntry{name: "other-main/", mode: os.ModeDir | 0o755},
		zipEntry{name: "other-main/README.md", body: "# other\n"},
		zipEntry{name: "other-main/src/main.go", body: "package main\n"},
	)
	dir := installedDir(t)
	s := serveArchive(t, http.StatusOK, data)
	o := opts(dir, s)
	o.Repo = "acme/other"
	_, _, err := Update(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "no vulnsuite templates") || !strings.Contains(err.Error(), "acme/other@main") {
		t.Fatalf("err = %v", err)
	}
	mustKeepOld(t, dir)
	if _, err := os.Stat(filepath.Join(dir, "README.md")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the unrelated repository must not be installed")
	}
}

func TestUpdateArchiveReplacesInstalledTemplates(t *testing.T) {
	// The caps leave a normal update alone: old tree replaced, nothing left over.
	dir := installedDir(t)
	s := serveArchive(t, http.StatusOK, templatesZip(t))
	_, version, err := Update(context.Background(), opts(dir, s))
	if err != nil {
		t.Fatal(err)
	}
	mustExist(t, filepath.Join(dir, "web", "x", "contract.yaml"))
	if _, err := os.Stat(filepath.Join(dir, "web", "old")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the old tree should be replaced")
	}
	if Version(dir) != version {
		t.Fatalf("Version = %q, want %q", Version(dir), version)
	}
	if sib := siblings(t, dir); len(sib) != 0 {
		t.Fatalf("leftovers: %v", sib)
	}
}

// Git metadata in an archive is refused (GHSA-g5pf-8pw3-4pwc): extracted, it
// would make the install a "checkout" whose config and hooks the next
// update-templates runs on the host. Case and Windows spellings count too.
func TestUpdateArchiveRejectsGitMetadata(t *testing.T) {
	for _, name := range []string{
		".git/config",
		".git/hooks/post-merge",
		".GIT/config",
		".git./config",
		"GIT~1/config",
		"web/x/.git/config",
		".git", // a gitfile pointing elsewhere
	} {
		t.Run(name, func(t *testing.T) {
			dir := installedDir(t)
			data := makeZip(t,
				zipEntry{name: "vulnsuite-templates-main/web/x/contract.yaml", body: contractBody},
				zipEntry{name: "vulnsuite-templates-main/" + name, body: "[core]\n\tfsmonitor = touch /tmp/pwned\n"},
			)
			s := serveArchive(t, http.StatusOK, data)
			_, _, err := Update(context.Background(), opts(dir, s))
			if err == nil || !strings.Contains(err.Error(), "git metadata") {
				t.Fatalf("err = %v", err)
			}
			mustKeepOld(t, dir)
		})
	}
}

// Names that merely contain "git" are ordinary files.
func TestHasGitSegment(t *testing.T) {
	for name, want := range map[string]bool{
		".git/config":       true,
		"a/.Git/HEAD":       true,
		"a/.git ":           true,
		"a\\.git\\config":   true,
		".gitignore":        false,
		".github/workflows": false,
		"web/git/contract":  false,
		"x.git/y":           false,
	} {
		if got := hasGitSegment(name); got != want {
			t.Errorf("hasGitSegment(%q) = %v, want %v", name, got, want)
		}
	}
}

// An archive install with a .git in it (from an older vulnsuite, or put there
// by hand) is still updated from the archive: git is never run in it.
func TestUpdateArchiveInstallIgnoresPlantedGit(t *testing.T) {
	dir := installedDir(t)
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if isRepoRoot(dir) {
		t.Fatal("an archive install must not count as a git checkout")
	}
	data := makeZip(t, zipEntry{name: "vulnsuite-templates-main/web/x/contract.yaml", body: contractBody})
	s := serveArchive(t, http.StatusOK, data)
	if _, _, err := Update(context.Background(), opts(dir, s)); err != nil {
		t.Fatal(err)
	}
	mustExist(t, filepath.Join(dir, "web", "x", "contract.yaml"))
	if _, err := os.Lstat(filepath.Join(dir, ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the planted .git should be gone with the old tree: %v", err)
	}
}
