// Package templates locates the templates directory and keeps it up to date
// from the vulnsuite-templates repository (like `nuclei -update-templates`).
package templates

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/loader"
)

// Defaults.
const (
	EnvDir         = "VULNSUITE_TEMPLATES"
	DefaultDirName = "vulnsuite-templates"
	DefaultRepo    = "ruzfi/vulnsuite-templates"
	DefaultBranch  = "main"
	versionFile    = ".vulnsuite-templates-version"
)

// DefaultDir is ~/vulnsuite-templates.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return DefaultDirName
	}
	return filepath.Join(home, DefaultDirName)
}

// Resolve picks the templates directory: an explicit flag, then $VULNSUITE_TEMPLATES,
// then the working directory when it holds templates, then ~/vulnsuite-templates.
func Resolve(flag string) (string, error) {
	if flag != "" {
		return filepath.Abs(flag)
	}
	if env := os.Getenv(EnvDir); env != "" {
		return filepath.Abs(env)
	}
	if cwd, err := os.Getwd(); err == nil {
		// The working directory itself, or any parent up to the enclosing git
		// repository root or archive install (so running from a subfolder of
		// a templates checkout works, without wandering into unrelated
		// parents).
		for _, dir := range candidateDirs(cwd) {
			if HasTemplates(dir) {
				return dir, nil
			}
		}
	}
	return DefaultDir(), nil
}

func candidateDirs(cwd string) []string {
	dirs := []string{cwd}
	dir := cwd
	for i := 0; i < maxRootDepth; i++ {
		if isTemplatesRoot(dir) {
			// Prefer the repository or install root (the whole templates
			// tree) over a subfolder of it.
			for i, j := 0, len(dirs)-1; i < j; i, j = i+1, j-1 {
				dirs[i], dirs[j] = dirs[j], dirs[i]
			}
			return dirs
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
		dirs = append(dirs, dir)
	}
	return dirs[:1] // not inside a repository: only cwd counts
}

// maxRootDepth bounds how many parents are searched for a templates root.
const maxRootDepth = 8

// isTemplatesRoot reports whether dir is the root of a templates tree: a git
// checkout, or an archive install carrying the version marker.
func isTemplatesRoot(dir string) bool {
	return isRepoRoot(dir) || isArchiveInstall(dir)
}

// isArchiveInstall reports whether dir was installed by update-templates.
func isArchiveInstall(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, versionFile))
	return err == nil && fi.Mode().IsRegular()
}

// enclosingInstall returns the nearest proper ancestor of dir (searching
// maxRootDepth levels) that is an archive install, or "".
func enclosingInstall(dir string) string {
	d := dir
	for i := 0; i < maxRootDepth; i++ {
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
		if isArchiveInstall(d) {
			return d
		}
	}
	return ""
}

func isRepoRoot(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// HasTemplates reports whether dir contains at least one vulnsuite contract
// within three levels. A file only counts when it declares a vulnsuite
// apiVersion: template.yaml is also the AWS SAM / CloudFormation file name,
// and an unrelated project must not be taken for a templates checkout (and
// then pulled or checked out by update-templates).
func HasTemplates(dir string) bool {
	found := false
	var walk func(string, int)
	walk = func(d string, depth int) {
		if found || depth > 3 {
			return
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range entries {
			if found {
				return
			}
			if e.IsDir() {
				if strings.HasPrefix(e.Name(), ".") || e.Name() == "node_modules" {
					continue
				}
				walk(filepath.Join(d, e.Name()), depth+1)
				continue
			}
			for _, n := range loader.ContractNames {
				if e.Name() == n && isContract(filepath.Join(d, n)) {
					found = true
					return
				}
			}
		}
	}
	walk(dir, 0)
	return found
}

// isContract reports whether the file at p declares a top-level
// `apiVersion: vulnsuite/...`, looking only at its first 64 KiB.
func isContract(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	head, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	for _, line := range strings.Split(string(head), "\n") {
		v, ok := strings.CutPrefix(line, "apiVersion:")
		if !ok {
			continue
		}
		if i := strings.Index(v, "#"); i >= 0 {
			v = v[:i]
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		return strings.HasPrefix(v, "vulnsuite/")
	}
	return false
}

// DefaultArchiveBaseURL serves GitHub repository archives as
// <base>/<owner>/<name>/zip/<ref>, where ref is a branch, tag or commit.
const DefaultArchiveBaseURL = "https://codeload.github.com"

// DefaultGitTimeout bounds each git network operation of an update.
const DefaultGitTimeout = 5 * time.Minute

// UpdateOptions tune an update.
type UpdateOptions struct {
	Dir  string // destination (default DefaultDir())
	Repo string // owner/name on GitHub (default DefaultRepo)
	// Ref is a branch, tag or commit. Empty means DefaultBranch for an
	// archive install, and "pull the current branch" for a git checkout.
	Ref string
	// Force replaces a non-empty Dir that update-templates did not install
	// (no .vulnsuite-templates-version marker).
	Force  bool
	Output io.Writer

	// ArchiveBaseURL overrides DefaultArchiveBaseURL (tests, mirrors).
	ArchiveBaseURL string
	// HTTPClient overrides the default client (10 minute timeout).
	HTTPClient *http.Client
	// GitTimeout overrides DefaultGitTimeout.
	GitTimeout time.Duration
}

// Update fetches the templates repository into Dir. A git checkout is pulled
// (or, with Ref, fetched and checked out detached; without Ref, a detached
// checkout returns to origin's default branch); otherwise Dir is replaced
// by the GitHub archive of Ref, but only when Dir is missing, empty or was
// installed by Update before, unless Force is set. It returns the directory
// and the version string recorded.
func Update(ctx context.Context, o UpdateOptions) (string, string, error) {
	if o.Dir == "" {
		o.Dir = DefaultDir()
	}
	if abs, err := filepath.Abs(o.Dir); err == nil {
		o.Dir = abs
	}
	if o.Output == nil {
		o.Output = io.Discard
	}
	if o.GitTimeout <= 0 {
		o.GitTimeout = DefaultGitTimeout
	}
	if isRepoRoot(o.Dir) {
		return updateGit(ctx, o)
	}
	if o.Repo == "" {
		o.Repo = DefaultRepo
	}
	if o.Ref == "" {
		o.Ref = DefaultBranch
	}
	if err := checkReplaceable(o.Dir, o.Force); err != nil {
		return o.Dir, "", err
	}
	return updateArchive(ctx, o)
}

// updateGit updates a git checkout in place. It never falls back to replacing
// the directory: that would discard .git and any uncommitted work.
func updateGit(ctx context.Context, o UpdateOptions) (string, string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return o.Dir, "", fmt.Errorf("%s is a git checkout but git is not on PATH; install git to update it (it is never replaced by an archive)", o.Dir)
	}
	git := func(timeout time.Duration, args ...string) (string, error) {
		cctx := ctx
		if timeout > 0 {
			var cancel context.CancelFunc
			cctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		cmd := exec.CommandContext(cctx, "git", append([]string{"-C", o.Dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never")
		out, err := cmd.CombinedOutput()
		if cctx.Err() == context.DeadlineExceeded {
			return string(out), fmt.Errorf("git %s: timed out after %s", args[0], timeout)
		}
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = err.Error()
			}
			return string(out), fmt.Errorf("git %s: %s", args[0], msg)
		}
		return string(out), nil
	}
	if o.Repo != "" && o.Repo != DefaultRepo {
		return o.Dir, "", fmt.Errorf("%s is a git checkout: -repo is not used for checkouts; change its remote with `git remote set-url origin`", o.Dir)
	}
	if o.Ref == "" {
		if _, err := git(o.GitTimeout, "symbolic-ref", "-q", "HEAD"); err == nil {
			fmt.Fprintf(o.Output, "git pull in %s\n", o.Dir)
			if _, err := git(o.GitTimeout, "pull", "--ff-only"); err != nil {
				return o.Dir, "", err
			}
		} else if err := returnToDefaultBranch(o, git); err != nil {
			return o.Dir, "", err
		}
	} else {
		if strings.HasPrefix(o.Ref, "-") {
			return o.Dir, "", fmt.Errorf("invalid ref %q", o.Ref)
		}
		status, err := git(o.GitTimeout, "status", "--porcelain", "--untracked-files=no")
		if err != nil {
			return o.Dir, "", err
		}
		if strings.TrimSpace(status) != "" {
			return o.Dir, "", fmt.Errorf("%s has uncommitted changes; commit or stash them before checking out -ref %s", o.Dir, o.Ref)
		}
		fmt.Fprintf(o.Output, "git fetch origin %s in %s\n", o.Ref, o.Dir)
		if _, err := git(o.GitTimeout, "fetch", "origin", "--", o.Ref); err != nil {
			return o.Dir, "", err
		}
		if _, err := git(o.GitTimeout, "checkout", "--detach", "FETCH_HEAD"); err != nil {
			return o.Dir, "", err
		}
	}
	rev, err := git(o.GitTimeout, "rev-parse", "--short", "HEAD")
	if err != nil {
		return o.Dir, "", err
	}
	return o.Dir, strings.TrimSpace(rev), nil
}

// returnToDefaultBranch handles a plain update of a checkout whose HEAD is
// detached (typically by an earlier -ref): it fetches origin and switches to
// the remote's default branch (origin/HEAD, else DefaultBranch), fast-forwarding
// it. It refuses, leaving the checkout untouched, when tracked files have
// uncommitted changes or when HEAD holds commits no branch or tag keeps.
func returnToDefaultBranch(o UpdateOptions, git func(time.Duration, ...string) (string, error)) error {
	status, err := git(o.GitTimeout, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return err
	}
	if strings.TrimSpace(status) != "" {
		return fmt.Errorf("%s is not on a branch (HEAD is detached, e.g. by -ref) and has uncommitted changes; commit or stash them, then rerun update-templates, or pass -ref to pick a ref", o.Dir)
	}
	fmt.Fprintf(o.Output, "git fetch origin in %s\n", o.Dir)
	if _, err := git(o.GitTimeout, "fetch", "origin"); err != nil {
		return err
	}
	branch := DefaultBranch
	if out, err := git(o.GitTimeout, "symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD"); err == nil {
		if b, ok := strings.CutPrefix(strings.TrimSpace(out), "origin/"); ok && b != "" {
			branch = b
		}
	}
	if strings.HasPrefix(branch, "-") {
		return fmt.Errorf("invalid default branch %q", branch)
	}
	remote := "refs/remotes/origin/" + branch
	if _, err := git(o.GitTimeout, "rev-parse", "--verify", "-q", remote); err != nil {
		return fmt.Errorf("%s is not on a branch (HEAD is detached) and origin has no %s branch; check out a branch yourself (git switch <branch>) or pass -ref", o.Dir, branch)
	}
	// Commits made on the detached HEAD would become unreachable: refuse.
	if out, err := git(o.GitTimeout, "for-each-ref", "--count=1", "--contains", "HEAD", "refs/heads", "refs/remotes", "refs/tags"); err != nil {
		return err
	} else if strings.TrimSpace(out) == "" {
		return fmt.Errorf("%s is not on a branch and HEAD has commits that no branch or tag keeps; save them on a branch (git switch -c <name>) before updating", o.Dir)
	}
	fmt.Fprintf(o.Output, "HEAD is detached; switching %s to %s (origin/%s)\n", o.Dir, branch, branch)
	if _, err := git(o.GitTimeout, "rev-parse", "--verify", "-q", "refs/heads/"+branch); err == nil {
		// An existing local branch is only fast-forwarded, never reset.
		if _, err := git(o.GitTimeout, "checkout", "-q", branch, "--"); err != nil {
			return err
		}
		if _, err := git(o.GitTimeout, "merge", "--ff-only", "-q", remote); err != nil {
			return fmt.Errorf("%w (local branch %s has diverged from origin/%s; reconcile it yourself)", err, branch, branch)
		}
		return nil
	}
	_, err = git(o.GitTimeout, "checkout", "-q", "--track", "-b", branch, "origin/"+branch, "--")
	return err
}

// checkReplaceable refuses to replace a directory update-templates did not
// create: it must be missing, empty, or carry the version marker. A directory
// inside an archive install is never replaced, even with force: that would
// put the whole archive in one of its own subfolders.
func checkReplaceable(dir string, force bool) error {
	if root := enclosingInstall(dir); root != "" {
		return fmt.Errorf("refusing to replace %s: it is inside the templates installed at %s; update that directory instead (-templates %s)", dir, root, root)
	}
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 || force {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, versionFile)); err == nil {
		return nil
	}
	return fmt.Errorf("refusing to replace %s: it is not empty and was not installed by update-templates (no %s marker); point -templates at another directory, or pass -force to replace it", dir, versionFile)
}

// Archive limits. A templates archive is a few MiB; the caps leave ample
// headroom while keeping a broken mirror or a zip bomb from exhausting memory
// or disk. A variable so tests can lower them.
var archiveLimits = struct {
	download int64 // compressed bytes downloaded
	extract  int64 // uncompressed bytes written, counted as they are written
	entries  int   // zip entries (files, directories, skipped symlinks)
}{
	download: 256 << 20,
	extract:  512 << 20,
	entries:  50_000,
}

func updateArchive(ctx context.Context, o UpdateOptions) (string, string, error) {
	base := strings.TrimRight(o.ArchiveBaseURL, "/")
	if base == "" {
		base = DefaultArchiveBaseURL
	}
	// zip/<ref> resolves branches, tags and commits alike, so a branch that
	// looks like a version (v2-dev) is not mistaken for a tag.
	url := fmt.Sprintf("%s/%s/zip/%s", base, o.Repo, o.Ref)
	fmt.Fprintf(o.Output, "downloading %s\n", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return o.Dir, "", err
	}
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return o.Dir, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return o.Dir, "", fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	parent, name := filepath.Dir(o.Dir), filepath.Base(o.Dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return o.Dir, "", err
	}
	// Stream the archive to disk next to the destination rather than into
	// memory, and give up once it exceeds the cap.
	zf, err := os.CreateTemp(parent, "."+name+".zip-")
	if err != nil {
		return o.Dir, "", err
	}
	defer func() {
		zf.Close()
		os.Remove(zf.Name())
	}()
	size, err := download(resp, zf, archiveLimits.download)
	if err != nil {
		return o.Dir, "", fmt.Errorf("download %s: %w; %s left unchanged", url, err, o.Dir)
	}

	tmp, err := os.MkdirTemp(parent, "."+name+".new-")
	if err != nil {
		return o.Dir, "", err
	}
	links, err := unzipStripTop(zf, size, tmp)
	if err != nil {
		os.RemoveAll(tmp)
		return o.Dir, "", fmt.Errorf("extract %s@%s: %w; %s left unchanged", o.Repo, o.Ref, err, o.Dir)
	}
	if len(links) > 0 {
		fmt.Fprintf(o.Output, "skipped %d symlink(s) in the archive (an archive install never creates symlinks; a template that needs one works only from a git checkout): %s\n", len(links), summarizePaths(links, 5))
	}
	if !HasTemplates(tmp) {
		os.RemoveAll(tmp)
		return o.Dir, "", fmt.Errorf("the archive of %s@%s contains no vulnsuite templates (no contract file); check -repo and -ref; %s left unchanged", o.Repo, o.Ref, o.Dir)
	}
	version := o.Repo + "@" + o.Ref + " " + time.Now().UTC().Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(tmp, versionFile), []byte(version+"\n"), 0o644); err != nil {
		os.RemoveAll(tmp)
		return o.Dir, "", err
	}
	if err := swapDir(tmp, o.Dir); err != nil {
		os.RemoveAll(tmp)
		return o.Dir, "", err
	}
	return o.Dir, version, nil
}

// download copies the response body to f, failing once it exceeds limit
// bytes, and returns the number of bytes written.
func download(resp *http.Response, f *os.File, limit int64) (int64, error) {
	if resp.ContentLength > limit {
		return 0, fmt.Errorf("archive is %d bytes, over the %d byte limit", resp.ContentLength, limit)
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return n, err
	}
	if n > limit {
		return n, fmt.Errorf("archive is over the %d byte limit", limit)
	}
	return n, nil
}

// swapDir moves newDir into place at dir. The previous dir is kept under a
// unique sibling name until newDir is in place, restored if that fails, and
// only then removed.
func swapDir(newDir, dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return os.Rename(newDir, dir)
	}
	old, err := os.MkdirTemp(filepath.Dir(dir), "."+filepath.Base(dir)+".old-")
	if err != nil {
		return err
	}
	// os.Rename cannot replace a directory on every platform; free the name.
	if err := os.Remove(old); err != nil {
		return err
	}
	if err := os.Rename(dir, old); err != nil {
		return err
	}
	if err := renameDir(newDir, dir); err != nil {
		if rerr := os.Rename(old, dir); rerr != nil {
			return fmt.Errorf("%w; the previous templates are kept at %s (restore failed: %v)", err, old, rerr)
		}
		return err
	}
	return os.RemoveAll(old)
}

// renameDir is os.Rename; a variable so tests can make the swap fail.
var renameDir = os.Rename

// Version returns the recorded version of a templates directory, if any.
func Version(dir string) string {
	if isRepoRoot(dir) {
		if rev, err := exec.Command("git", "-C", dir, "rev-parse", "--short", "HEAD").Output(); err == nil {
			return "git " + strings.TrimSpace(string(rev))
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, versionFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// errExtractLimit is returned once the extracted bytes exceed the cap.
var errExtractLimit = errors.New("archive expands beyond the size limit")

// summarizePaths joins up to max paths, noting how many more there are.
func summarizePaths(paths []string, max int) string {
	if len(paths) <= max {
		return strings.Join(paths, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(paths[:max], ", "), len(paths)-max)
}

// unzipStripTop extracts a GitHub archive (single top-level folder) into dst.
// Only directories and regular files are extracted: symlinks (and any other
// special entries) are skipped, and entries escaping dst are rejected. The
// number of entries and the total bytes written are capped by archiveLimits;
// bytes are counted as written, whatever sizes the entry headers declare.
// It returns the archive paths (top folder stripped) of the skipped symlinks.
func unzipStripTop(r io.ReaderAt, size int64, dst string) ([]string, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	if n := len(zr.File); n > archiveLimits.entries {
		return nil, fmt.Errorf("archive has %d entries, over the %d entry limit", n, archiveLimits.entries)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return nil, err
	}
	var links []string
	root := filepath.Clean(dst) + string(os.PathSeparator)
	budget := archiveLimits.extract
	for _, f := range zr.File {
		name := f.Name
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[i+1:]
		} else {
			continue
		}
		if name == "" {
			continue
		}
		target := filepath.Join(dst, filepath.FromSlash(name))
		if !strings.HasPrefix(target, root) {
			return links, errors.New("archive contains an unsafe path: " + f.Name)
		}
		mode := f.Mode()
		if mode.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return links, err
			}
			continue
		}
		if !mode.IsRegular() {
			// symlink, device, ...: never materialise it
			if mode&os.ModeSymlink != 0 {
				links = append(links, name)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return links, err
		}
		n, err := extractFile(f, target, budget)
		if err != nil {
			if errors.Is(err, errExtractLimit) {
				return links, fmt.Errorf("%w of %d bytes (at %s)", err, archiveLimits.extract, f.Name)
			}
			return links, err
		}
		budget -= n
	}
	return links, nil
}

// extractFile writes f to target, at most budget bytes; one byte more fails
// with errExtractLimit. It returns the bytes written.
func extractFile(f *zip.File, target string, budget int64) (int64, error) {
	perm := os.FileMode(0o644)
	if f.Mode()&0o111 != 0 {
		perm = 0o755
	}
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	// O_EXCL: never follow or overwrite something already at target.
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, io.LimitReader(rc, budget+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > budget {
		err = errExtractLimit
	}
	return n, err
}
