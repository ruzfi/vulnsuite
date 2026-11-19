package templates

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type zipEntry struct {
	name, body string
	mode       os.FileMode
}

func makeZip(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func templatesZip(t *testing.T) []byte {
	return makeZip(t,
		zipEntry{name: "vulnsuite-templates-main/", mode: os.ModeDir | 0o755},
		zipEntry{name: "vulnsuite-templates-main/web/x/contract.yaml", body: "apiVersion: vulnsuite/v1\nkind: Target\n"},
	)
}

type archiveServer struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func (s *archiveServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

func serveArchive(t *testing.T, status int, body []byte) *archiveServer {
	t.Helper()
	s := &archiveServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		s.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func opts(dir string, s *archiveServer) UpdateOptions {
	return UpdateOptions{Dir: dir, ArchiveBaseURL: s.URL, HTTPClient: s.Client()}
}

// siblings lists the entries of dir's parent other than dir itself, to catch
// leftover .new/.old directories.
func siblings(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.Name() != filepath.Base(dir) {
			out = append(out, e.Name())
		}
	}
	return out
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("%s should exist: %v", path, err)
	}
}

func TestUpdateArchiveFreshInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tpl")
	s := serveArchive(t, http.StatusOK, templatesZip(t))
	got, version, err := Update(context.Background(), opts(dir, s))
	if err != nil {
		t.Fatal(err)
	}
	if got != dir || !strings.HasPrefix(version, DefaultRepo+"@"+DefaultBranch+" ") {
		t.Fatalf("dir=%s version=%q", got, version)
	}
	if p := s.requests(); len(p) != 1 || p[0] != "/"+DefaultRepo+"/zip/"+DefaultBranch {
		t.Fatalf("requests: %v", p)
	}
	mustExist(t, filepath.Join(dir, "web", "x", "contract.yaml"))
	if !HasTemplates(dir) || Version(dir) != version {
		t.Fatalf("HasTemplates=%v Version=%q", HasTemplates(dir), Version(dir))
	}
	if sib := siblings(t, dir); len(sib) != 0 {
		t.Fatalf("leftovers: %v", sib)
	}
}

func TestUpdateArchiveRefUsesGenericZipURL(t *testing.T) {
	// A branch named like a version must not be fetched as refs/tags/.
	for _, ref := range []string{"v2-dev", "v1.2.0", "feature/x"} {
		dir := filepath.Join(t.TempDir(), "tpl")
		s := serveArchive(t, http.StatusOK, templatesZip(t))
		o := opts(dir, s)
		o.Ref, o.Repo = ref, "acme/tpl"
		if _, _, err := Update(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		if p := s.requests(); len(p) != 1 || p[0] != "/acme/tpl/zip/"+ref {
			t.Fatalf("ref %s: requests %v", ref, p)
		}
	}
}

func TestUpdateRefusesUnrelatedDirectory(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "important.txt")
	if err := os.WriteFile(keep, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := serveArchive(t, http.StatusOK, templatesZip(t))
	_, _, err := Update(context.Background(), opts(dir, s))
	if err == nil || !strings.Contains(err.Error(), "refusing to replace") || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("err = %v", err)
	}
	mustExist(t, keep)
	if len(s.requests()) != 0 {
		t.Fatal("nothing should be downloaded for a refused directory")
	}

	// -force replaces it.
	o := opts(dir, s)
	o.Force = true
	if _, _, err := Update(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keep); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("forced update should replace the directory: %v", err)
	}
	mustExist(t, filepath.Join(dir, "web", "x", "contract.yaml"))
}

func TestUpdateRefusesFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := serveArchive(t, http.StatusOK, templatesZip(t))
	o := opts(f, s)
	o.Force = true
	if _, _, err := Update(context.Background(), o); err == nil {
		t.Fatal("a file must not be replaced")
	}
	mustExist(t, f)
}

func TestUpdateReplacesEmptyAndInstalledDirs(t *testing.T) {
	s := serveArchive(t, http.StatusOK, templatesZip(t))

	empty := filepath.Join(t.TempDir(), "tpl")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Update(context.Background(), opts(empty, s)); err != nil {
		t.Fatal(err)
	}

	installed := filepath.Join(t.TempDir(), "tpl")
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(installed, "stale.yaml")
	_ = os.WriteFile(stale, []byte("old"), 0o644)
	_ = os.WriteFile(filepath.Join(installed, versionFile), []byte("old\n"), 0o644)
	// A user's unrelated sibling with the old fixed suffix must survive.
	userOld := installed + ".old"
	if err := os.Mkdir(userOld, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Update(context.Background(), opts(installed, s)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale file should be gone after an update")
	}
	mustExist(t, userOld)
	if sib := siblings(t, installed); len(sib) != 1 {
		t.Fatalf("leftovers: %v", sib)
	}
}

func TestUpdateDownloadFailureKeepsDirectory(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, versionFile), []byte("old\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("a"), 0o644)
	for _, s := range []*archiveServer{
		serveArchive(t, http.StatusNotFound, nil),
		serveArchive(t, http.StatusOK, []byte("not a zip")),
	} {
		if _, _, err := Update(context.Background(), opts(dir, s)); err == nil {
			t.Fatal("expected an error")
		}
		mustExist(t, filepath.Join(dir, "a.yaml"))
		if sib := siblings(t, dir); len(sib) != 0 {
			t.Fatalf("leftovers: %v", sib)
		}
	}
}

func TestSwapRestoresOnFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tpl")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, versionFile), []byte("old\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("a"), 0o644)
	orig := renameDir
	renameDir = func(string, string) error { return errors.New("boom") }
	t.Cleanup(func() { renameDir = orig })

	s := serveArchive(t, http.StatusOK, templatesZip(t))
	if _, _, err := Update(context.Background(), opts(dir, s)); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
	mustExist(t, filepath.Join(dir, "a.yaml"))
	if sib := siblings(t, dir); len(sib) != 0 {
		t.Fatalf("leftovers: %v", sib)
	}
}

func TestUpdateGitCheckoutWithoutGit(t *testing.T) {
	dir := t.TempDir()
	_ = os.Mkdir(filepath.Join(dir, ".git"), 0o755)
	wip := filepath.Join(dir, "wip.yaml")
	_ = os.WriteFile(wip, []byte("wip"), 0o644)
	t.Setenv("PATH", t.TempDir()) // no git
	s := serveArchive(t, http.StatusOK, templatesZip(t))
	for _, force := range []bool{false, true} {
		o := opts(dir, s)
		o.Force = force
		_, _, err := Update(context.Background(), o)
		if err == nil || !strings.Contains(err.Error(), "git is not on PATH") {
			t.Fatalf("force=%v: err = %v", force, err)
		}
	}
	mustExist(t, filepath.Join(dir, ".git"))
	mustExist(t, wip)
	if len(s.requests()) != 0 {
		t.Fatal("a git checkout must never fall back to the archive")
	}
}

func TestUpdateGitTimeoutAndNoPrompt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake git")
	}
	// Two independent checks, neither racing a deadline against process start
	// (which made the old combined version flaky under `go test -race` load):
	// the prompt is checked by a fake git that exits at once, and the timeout
	// by one that never exits, measured against a bound far from both.
	fakeGit := func(t *testing.T, script string) string {
		t.Helper()
		dir := t.TempDir()
		_ = os.Mkdir(filepath.Join(dir, ".git"), 0o755)
		bin := t.TempDir()
		if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		return dir
	}

	t.Run("no prompt", func(t *testing.T) {
		envOut := filepath.Join(t.TempDir(), "env")
		dir := fakeGit(t, "echo \"$GIT_TERMINAL_PROMPT $GCM_INTERACTIVE\" > '"+envOut+"'\necho fatal: no >&2\nexit 1\n")
		_, _, err := Update(context.Background(), UpdateOptions{Dir: dir, Output: io.Discard, GitTimeout: time.Hour})
		if err == nil || strings.Contains(err.Error(), "timed out") {
			t.Fatalf("err = %v", err)
		}
		b, _ := os.ReadFile(envOut)
		if strings.TrimSpace(string(b)) != "0 never" {
			t.Fatalf("GIT_TERMINAL_PROMPT GCM_INTERACTIVE = %q", b)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		dir := fakeGit(t, "exec sleep 300\n")
		start := time.Now()
		_, _, err := Update(context.Background(), UpdateOptions{Dir: dir, Output: io.Discard, GitTimeout: 100 * time.Millisecond})
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("err = %v", err)
		}
		if el := time.Since(start); el > time.Minute {
			t.Fatalf("timeout not enforced: returned after %v", el)
		}
	})
}

// gitRepo sets up an origin repository and a clone of it, isolated from the
// user's git configuration.
func gitRepo(t *testing.T) (origin, clone string, git func(dir string, args ...string) string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "t")
	t.Setenv("GIT_AUTHOR_EMAIL", "t@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@example.invalid")
	git = func(dir string, args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	root := t.TempDir()
	origin = filepath.Join(root, "origin")
	clone = filepath.Join(root, "clone")
	_ = os.Mkdir(origin, 0o755)
	git(origin, "init", "-q", "-b", "main")
	_ = os.WriteFile(filepath.Join(origin, "a.yaml"), []byte("v1"), 0o644)
	git(origin, "add", ".")
	git(origin, "commit", "-q", "-m", "one")
	git(origin, "tag", "v1")
	git(root, "clone", "-q", origin, clone)
	return origin, clone, git
}

func TestUpdateGitPullAndRef(t *testing.T) {
	origin, clone, git := gitRepo(t)
	v1 := git(origin, "rev-parse", "--short", "HEAD")
	_ = os.WriteFile(filepath.Join(origin, "a.yaml"), []byte("v2"), 0o644)
	git(origin, "commit", "-q", "-am", "two")
	v2 := git(origin, "rev-parse", "--short", "HEAD")
	// A branch that looks like a version tag.
	git(origin, "branch", "v2-dev", v1)

	ctx := context.Background()
	// No -ref: fast-forward the current branch.
	_, rev, err := Update(ctx, UpdateOptions{Dir: clone})
	if err != nil || rev != v2 {
		t.Fatalf("pull: rev=%s err=%v (want %s)", rev, err, v2)
	}
	// -ref tag: fetched and checked out detached.
	_, rev, err = Update(ctx, UpdateOptions{Dir: clone, Ref: "v1"})
	if err != nil || rev != v1 {
		t.Fatalf("-ref v1: rev=%s err=%v (want %s)", rev, err, v1)
	}
	if b, _ := os.ReadFile(filepath.Join(clone, "a.yaml")); string(b) != "v1" {
		t.Fatalf("a.yaml = %q", b)
	}
	// -ref branch named like a tag.
	_, rev, err = Update(ctx, UpdateOptions{Dir: clone, Ref: "main"})
	if err != nil || rev != v2 {
		t.Fatalf("-ref main: rev=%s err=%v", rev, err)
	}
	_, rev, err = Update(ctx, UpdateOptions{Dir: clone, Ref: "v2-dev"})
	if err != nil || rev != v1 {
		t.Fatalf("-ref v2-dev: rev=%s err=%v", rev, err)
	}

	// Uncommitted changes to tracked files: refused, work kept.
	_ = os.WriteFile(filepath.Join(clone, "a.yaml"), []byte("wip"), 0o644)
	if _, _, err := Update(ctx, UpdateOptions{Dir: clone, Ref: "main"}); err == nil || !strings.Contains(err.Error(), "uncommitted") {
		t.Fatalf("dirty: err = %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(clone, "a.yaml")); string(b) != "wip" {
		t.Fatalf("uncommitted work lost: %q", b)
	}

	// Unknown ref and option-like ref: errors, checkout untouched.
	git(clone, "checkout", "-q", "--", "a.yaml")
	if _, _, err := Update(ctx, UpdateOptions{Dir: clone, Ref: "no-such-ref"}); err == nil {
		t.Fatal("unknown ref should fail")
	}
	if _, _, err := Update(ctx, UpdateOptions{Dir: clone, Ref: "--upload-pack=x"}); err == nil {
		t.Fatal("option-like ref should fail")
	}
	// -repo is not applied to a checkout.
	if _, _, err := Update(ctx, UpdateOptions{Dir: clone, Repo: "acme/other"}); err == nil || !strings.Contains(err.Error(), "-repo") {
		t.Fatalf("-repo: err = %v", err)
	}
}

// A plain update after -ref (which leaves HEAD detached) returns to origin's
// default branch instead of failing in `git pull`, without losing work.
func TestUpdateGitAfterRefReturnsToDefaultBranch(t *testing.T) {
	origin, clone, git := gitRepo(t)
	ctx := context.Background()
	branchOf := func() string {
		t.Helper()
		out, err := exec.Command("git", "-C", clone, "symbolic-ref", "-q", "--short", "HEAD").Output()
		if err != nil {
			return "(detached)"
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(content string) string {
		t.Helper()
		_ = os.WriteFile(filepath.Join(origin, "a.yaml"), []byte(content), 0o644)
		git(origin, "commit", "-q", "-am", content)
		return git(origin, "rev-parse", "--short", "HEAD")
	}

	if _, _, err := Update(ctx, UpdateOptions{Dir: clone, Ref: "v1"}); err != nil {
		t.Fatal(err)
	}
	if b := branchOf(); b != "(detached)" {
		t.Fatalf("-ref should detach, on %s", b)
	}
	v2 := commit("v2")
	_, rev, err := Update(ctx, UpdateOptions{Dir: clone})
	if err != nil || rev != v2 || branchOf() != "main" {
		t.Fatalf("after -ref: rev=%s err=%v branch=%s (want %s on main)", rev, err, branchOf(), v2)
	}
	// ...and plain pulls keep working from there.
	v3 := commit("v3")
	if _, rev, err := Update(ctx, UpdateOptions{Dir: clone}); err != nil || rev != v3 {
		t.Fatalf("second pull: rev=%s err=%v", rev, err)
	}

	// Detached with uncommitted changes to tracked files: refused, work kept.
	if _, _, err := Update(ctx, UpdateOptions{Dir: clone, Ref: "v1"}); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(clone, "a.yaml"), []byte("wip"), 0o644)
	if _, _, err := Update(ctx, UpdateOptions{Dir: clone}); err == nil || !strings.Contains(err.Error(), "uncommitted") {
		t.Fatalf("dirty detached: err = %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(clone, "a.yaml")); string(b) != "wip" || branchOf() != "(detached)" {
		t.Fatalf("dirty detached: a.yaml=%q branch=%s", b, branchOf())
	}

	// Commits made on the detached HEAD are not orphaned: refused.
	git(clone, "commit", "-q", "-am", "local work")
	local := git(clone, "rev-parse", "--short", "HEAD")
	if _, _, err := Update(ctx, UpdateOptions{Dir: clone}); err == nil || !strings.Contains(err.Error(), "no branch or tag keeps") {
		t.Fatalf("orphan commits: err = %v", err)
	}
	if got := git(clone, "rev-parse", "--short", "HEAD"); got != local {
		t.Fatalf("orphan commits: HEAD moved to %s", got)
	}

	// No local default branch yet, and origin/HEAD names another branch: a
	// tracking branch is created for it.
	git(origin, "branch", "trunk", "main")
	v4 := commit("v4") // on main only
	git(clone, "checkout", "-q", "--detach", "v1")
	git(clone, "fetch", "-q", "origin")
	git(clone, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")
	_, rev, err = Update(ctx, UpdateOptions{Dir: clone})
	if err != nil || branchOf() != "trunk" || rev != v3 {
		t.Fatalf("origin/HEAD=trunk: rev=%s err=%v branch=%s (want %s on trunk, not %s)", rev, err, branchOf(), v3, v4)
	}
	if up := git(clone, "rev-parse", "--abbrev-ref", "trunk@{upstream}"); up != "origin/trunk" {
		t.Fatalf("trunk upstream = %s", up)
	}
}

func TestUnzipSkipsSymlinks(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "out")
	data := makeZip(t,
		zipEntry{name: "top/", mode: os.ModeDir | 0o755},
		zipEntry{name: "top/real.yaml", body: "id: x\n"},
		zipEntry{name: "top/script.sh", body: "#!/bin/sh\n", mode: 0o755},
		zipEntry{name: "top/link", body: "real.yaml", mode: os.ModeSymlink | 0o777},
		zipEntry{name: "top/escape", body: "/etc/passwd", mode: os.ModeSymlink | 0o777},
	)
	if err := unzipBytes(data, dst); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"link", "escape"} {
		if _, err := os.Lstat(filepath.Join(dst, n)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("symlink entry %s should be skipped: %v", n, err)
		}
	}
	fi, err := os.Stat(filepath.Join(dst, "real.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi.Mode().Perm() != 0o644 {
			t.Fatalf("real.yaml mode %v", fi.Mode())
		}
		if fi, err := os.Stat(filepath.Join(dst, "script.sh")); err != nil || fi.Mode().Perm()&0o100 == 0 {
			t.Fatalf("script.sh should stay executable: %v %v", fi, err)
		}
	}
}

func TestUnzipRejectsEscapingPaths(t *testing.T) {
	parent := t.TempDir()
	dst := filepath.Join(parent, "out")
	for _, name := range []string{"top/../../evil.yaml", "top/a/../../../evil.yaml"} {
		data := makeZip(t, zipEntry{name: name, body: "x"})
		if err := unzipBytes(data, dst); err == nil || !strings.Contains(err.Error(), "unsafe path") {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(parent, "evil.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("entry escaped the destination")
	}
}

// Only files declaring a vulnsuite apiVersion count: template.yaml is also
// the AWS SAM / CloudFormation file name.
func TestHasTemplatesNeedsVulnsuiteContract(t *testing.T) {
	write := func(dir, name, body string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sam := t.TempDir()
	write(sam, "template.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nTransform: AWS::Serverless-2016-10-31\n")
	write(filepath.Join(sam, "infra"), "contract.yaml", "apiVersion: v1\nkind: Contract\n")
	if HasTemplates(sam) {
		t.Error("a SAM project counts as a templates directory")
	}
	for _, v := range []string{"apiVersion: vulnsuite/v1", `apiVersion: "vulnsuite/v1"`, "apiVersion: 'vulnsuite/v1' # pinned"} {
		dir := t.TempDir()
		write(filepath.Join(dir, "web", "x"), "template.yaml", "# a target\n"+v+"\nkind: Target\n")
		if !HasTemplates(dir) {
			t.Errorf("%q not recognised", v)
		}
	}
}

// Running from inside an unrelated git repository that happens to hold a
// template.yaml must not resolve to that repository: update-templates would
// then git pull, or with -ref check out a detached commit, in the user's own
// project.
func TestResolveIgnoresUnrelatedRepo(t *testing.T) {
	t.Setenv(EnvDir, "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(repo, "template.yaml"), []byte("AWSTemplateFormatVersion: '2010-09-09'\n"), 0o644)
	src := filepath.Join(repo, "src")
	os.Mkdir(src, 0o755)
	t.Chdir(src)
	got, err := Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if got != DefaultDir() {
		t.Fatalf("Resolve = %q, want the default %q", got, DefaultDir())
	}
	// A real templates checkout is still found from a subfolder.
	os.WriteFile(filepath.Join(repo, "template.yaml"), []byte("apiVersion: vulnsuite/v1\nkind: Target\n"), 0o644)
	got, err = Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(repo); got != repo && got != want {
		t.Fatalf("Resolve = %q, want %q", got, repo)
	}
}

// #94 item 2: inside an archive install (no .git, only the version marker),
// a subfolder resolves to the install root, not to itself.
func TestResolveArchiveInstallFromSubfolder(t *testing.T) {
	t.Setenv(EnvDir, "")
	t.Setenv("HOME", t.TempDir())
	root := filepath.Join(t.TempDir(), "tpl")
	sub := filepath.Join(root, "web-apps")
	if err := os.MkdirAll(filepath.Join(sub, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(sub, "x", "contract.yaml"), []byte("apiVersion: vulnsuite/v1\nkind: Target\n"), 0o644)
	os.WriteFile(filepath.Join(root, versionFile), []byte("ruzfi/vulnsuite-templates@main\n"), 0o644)
	t.Chdir(sub)
	got, err := Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(root); got != root && got != want {
		t.Fatalf("Resolve = %q, want the install root %q", got, root)
	}
}

// #94 item 2: update-templates never replaces a subfolder of an archive
// install with the whole archive, even with -force.
func TestUpdateRefusesSubfolderOfInstall(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tpl")
	sub := filepath.Join(root, "web-apps")
	keep := filepath.Join(sub, "x", "contract.yaml")
	if err := os.MkdirAll(filepath.Dir(keep), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(keep, []byte("apiVersion: vulnsuite/v1\nkind: Target\n"), 0o644)
	os.WriteFile(filepath.Join(root, versionFile), []byte("old\n"), 0o644)
	s := serveArchive(t, http.StatusOK, templatesZip(t))
	o := opts(sub, s)
	o.Force = true
	_, _, err := Update(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "inside the templates installed at "+root) {
		t.Fatalf("err = %v", err)
	}
	mustExist(t, keep)
	if len(s.requests()) != 0 {
		t.Fatal("nothing should be downloaded for a refused directory")
	}
	// The install root itself still updates.
	if _, _, err := Update(context.Background(), opts(root, s)); err != nil {
		t.Fatal(err)
	}
	mustExist(t, filepath.Join(root, "web", "x", "contract.yaml"))
}
