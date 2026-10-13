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

// UpdateOptions tune an update.
type UpdateOptions struct {
	Dir    string // destination (default DefaultDir())
	Repo   string // owner/name on GitHub (default DefaultRepo)
	Ref    string // branch or tag (default DefaultBranch)
	Output io.Writer
}

// Update fetches the templates repository into Dir. A git checkout is pulled;
// anything else is replaced by the GitHub archive of Ref. It returns the
// directory and the version string recorded.
func Update(ctx context.Context, o UpdateOptions) (string, string, error) {
	if o.Dir == "" {
		o.Dir = DefaultDir()
	}
	if o.Repo == "" {
		o.Repo = DefaultRepo
	}
	if o.Ref == "" {
		o.Ref = DefaultBranch
	}
	if o.Output == nil {
		o.Output = io.Discard
	}
	if isRepoRoot(o.Dir) {
		if _, err := exec.LookPath("git"); err == nil {
			fmt.Fprintf(o.Output, "git pull in %s\n", o.Dir)
			cmd := exec.CommandContext(ctx, "git", "-C", o.Dir, "pull", "--ff-only")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return o.Dir, "", fmt.Errorf("git pull: %s", strings.TrimSpace(string(out)))
			}
			rev, _ := exec.CommandContext(ctx, "git", "-C", o.Dir, "rev-parse", "--short", "HEAD").Output()
			return o.Dir, strings.TrimSpace(string(rev)), nil
		}
	}
	url := fmt.Sprintf("https://codeload.github.com/%s/zip/refs/heads/%s", o.Repo, o.Ref)
	if looksLikeTag(o.Ref) {
		url = fmt.Sprintf("https://codeload.github.com/%s/zip/refs/tags/%s", o.Repo, o.Ref)
	}
	fmt.Fprintf(o.Output, "downloading %s\n", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return o.Dir, "", err
	}
	client := &http.Client{Timeout: 10 * time.Minute}
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
	tmp := o.Dir + ".new"
	os.RemoveAll(tmp)
	if err := unzipStripTop(data, tmp); err != nil {
		os.RemoveAll(tmp)
		return o.Dir, "", err
	}
	old := o.Dir + ".old"
	os.RemoveAll(old)
	if _, err := os.Stat(o.Dir); err == nil {
		if err := os.Rename(o.Dir, old); err != nil {
			os.RemoveAll(tmp)
			return o.Dir, "", err
		}
	}
	if err := os.Rename(tmp, o.Dir); err != nil {
		os.Rename(old, o.Dir)
		return o.Dir, "", err
	}
	os.RemoveAll(old)
	version := o.Repo + "@" + o.Ref + " " + time.Now().UTC().Format(time.RFC3339)
	_ = os.WriteFile(filepath.Join(o.Dir, versionFile), []byte(version+"\n"), 0o644)
	return o.Dir, version, nil
}

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

func looksLikeTag(ref string) bool {
	return strings.HasPrefix(ref, "v") && len(ref) > 1 && ref[1] >= '0' && ref[1] <= '9'
}

// unzipStripTop extracts a GitHub archive (single top-level folder) into dst.
func unzipStripTop(data []byte, dst string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
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
		if !strings.HasPrefix(target, filepath.Clean(dst)+string(os.PathSeparator)) {
			return errors.New("archive contains an unsafe path: " + f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode().Perm()|0o600)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
