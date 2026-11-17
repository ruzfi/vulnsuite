// Package templates locates the templates directory and keeps it up to date
// from the vulnsuite-templates repository (like `nuclei -update-templates`).
package templates

import (
	"archive/zip"
	"bytes"
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
		// repository root (so running from a subfolder of a templates checkout
		// works, without wandering into unrelated parents).
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
	for i := 0; i < 8; i++ {
		if isRepoRoot(dir) {
			// Prefer the repository root (the whole templates tree) over a
			// subfolder of it.
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

func isRepoRoot(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// HasTemplates reports whether dir contains at least one contract within three levels.
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
				if e.Name() == n {
					found = true
					return
				}
			}
		}
	}
	walk(dir, 0)
	return found
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
// (or, with Ref, fetched and checked out detached); otherwise Dir is replaced
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
		fmt.Fprintf(o.Output, "git pull in %s\n", o.Dir)
		if _, err := git(o.GitTimeout, "pull", "--ff-only"); err != nil {
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

// checkReplaceable refuses to replace a directory update-templates did not
// create: it must be missing, empty, or carry the version marker.
func checkReplaceable(dir string, force bool) error {
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<30))
	if err != nil {
		return o.Dir, "", err
	}

	parent, name := filepath.Dir(o.Dir), filepath.Base(o.Dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return o.Dir, "", err
	}
	tmp, err := os.MkdirTemp(parent, "."+name+".new-")
	if err != nil {
		return o.Dir, "", err
	}
	if err := unzipStripTop(data, tmp); err != nil {
		os.RemoveAll(tmp)
		return o.Dir, "", err
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

// unzipStripTop extracts a GitHub archive (single top-level folder) into dst.
// Only directories and regular files are extracted: symlinks (and any other
// special entries) are skipped, and entries escaping dst are rejected.
func unzipStripTop(data []byte, dst string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	root := filepath.Clean(dst) + string(os.PathSeparator)
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
			return errors.New("archive contains an unsafe path: " + f.Name)
		}
		mode := f.Mode()
		if mode.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if !mode.IsRegular() {
			continue // symlink, device, ...: never materialise it
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := extractFile(f, target); err != nil {
			return err
		}
	}
	return nil
}

func extractFile(f *zip.File, target string) error {
	perm := os.FileMode(0o644)
	if f.Mode()&0o111 != 0 {
		perm = 0o755
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	// O_EXCL: never follow or overwrite something already at target.
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, rc)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}
