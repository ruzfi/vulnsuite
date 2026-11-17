package contract

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Templates are untrusted input: every path a contract names (overlay src,
// patch, build context, dockerfile) must stay inside the template folder, and
// every value that ends up in a generated Dockerfile must not be able to add
// instructions to it.

// ErrPathEscapes is returned when a template path leaves the template folder.
var ErrPathEscapes = errors.New("path escapes the template folder")

var driveRe = regexp.MustCompile(`^[A-Za-z]:`)

// checkLocalPath reports whether p is a relative, lexically local path: not
// empty, not absolute (POSIX or Windows), no control characters, and no ".."
// segment at all. Backslashes count as separators so
// the check means the same on every OS.
func checkLocalPath(p string) error {
	if p == "" {
		return errors.New("must not be empty")
	}
	if hasControl(p) {
		return errors.New("must not contain control characters")
	}
	s := strings.ReplaceAll(p, `\`, "/")
	if path.IsAbs(s) || driveRe.MatchString(s) {
		return errors.New("must be a relative path inside the template folder")
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == ".." {
			return errors.New("must not contain .. segments (stay inside the template folder)")
		}
	}
	return nil
}

// destCharRe is the character set allowed in an overlay dest: enough for any
// real file path, and nothing a Dockerfile COPY/RUN line or a shell would
// treat specially (whitespace, quotes, $, `, ;, globs, backslashes, ...).
var destCharRe = regexp.MustCompile(`^[A-Za-z0-9._@%+=:,/-]+$`)

// checkOverlayDest validates an overlay destination. absolute is required for
// an image base, where dest is a path in the image; for a source/build base it
// is a path in the build context and may be relative.
func checkOverlayDest(dest string, absolute bool) error {
	if !destCharRe.MatchString(dest) {
		return errors.New("must be a plain path (letters, digits and . _ @ % + = : , / -; no whitespace, quotes, $ or control characters)")
	}
	if absolute && !strings.HasPrefix(dest, "/") {
		return errors.New("must be an absolute path in the image for an image base")
	}
	for _, seg := range strings.Split(dest, "/") {
		if seg == ".." {
			return errors.New("must not contain .. segments")
		}
	}
	if strings.Trim(dest, "/.") == "" {
		return errors.New("must name a file, not the root")
	}
	return nil
}

// CheckOverlayDest is checkOverlayDest for the builder's defence-in-depth check.
func CheckOverlayDest(dest string, absolute bool) error { return checkOverlayDest(dest, absolute) }

// envKeyRe is a portable environment variable name.
var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// CheckEnv validates an environment entry that is baked into a Dockerfile ENV
// line: a plain variable name and a value without control characters (a
// newline would start a new Dockerfile instruction).
func CheckEnv(k, v string) error {
	if !envKeyRe.MatchString(k) {
		return fmt.Errorf("variable name %q must match %s", k, envKeyRe)
	}
	if hasControl(v) {
		return fmt.Errorf("value of %s must not contain newlines or other control characters", k)
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
			return true
		}
	}
	return false
}

// TemplatePath resolves a template-relative path (slash-separated, as written
// in the contract) to a real path on disk, following symlinks, and refuses it
// when the result is outside the template folder. The returned path is the
// resolved one, so callers read exactly what was checked.
//
// A path that does not exist is returned joined but unresolved together with
// the os error, so callers can still report "missing".
func (c *Contract) TemplatePath(rel string) (string, error) {
	return ConfinedPath(c.Folder, rel)
}

// ConfinedPath is TemplatePath for an arbitrary root folder.
func ConfinedPath(root, rel string) (string, error) {
	if err := checkLocalPath(rel); err != nil {
		return "", fmt.Errorf("%s: %w: %v", rel, ErrPathEscapes, err)
	}
	joined := filepath.Join(root, filepath.FromSlash(strings.ReplaceAll(rel, `\`, "/")))
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return joined, err
	}
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return joined, err // typically os.ErrNotExist: the caller reports it missing
	}
	if !within(realRoot, resolved) {
		return "", fmt.Errorf("%s: %w (resolves to %s)", rel, ErrPathEscapes, resolved)
	}
	return resolved, nil
}

// within reports whether p is root or below it (both already resolved).
func within(root, p string) bool {
	r, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return r == "." || (r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)))
}
