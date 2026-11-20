package builder

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// dockerignore is a parsed .dockerignore: patterns are matched in order and
// the last one that matches a path (or one of its parent directories) wins,
// with "!" marking an exception, as the Docker CLI does.
type dockerignore struct {
	rules         []ignoreRule
	hasExceptions bool
}

type ignoreRule struct {
	match     func(name string) bool
	exception bool
}

// readDockerignore reads root/.dockerignore; a missing file ignores nothing.
// A symlinked .dockerignore is refused like any other context symlink read.
func readDockerignore(root string) (*dockerignore, error) {
	p := filepath.Join(root, ".dockerignore")
	info, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return &dockerignore{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New(".dockerignore is not a regular file")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return parseDockerignore(data)
}

func parseDockerignore(data []byte) (*dockerignore, error) {
	d := &dockerignore{}
	sc := bufio.NewScanner(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	for n := 1; sc.Scan(); n++ {
		// As in Docker, only a line starting with "#" is a comment: the
		// check comes before trimming, so "  # x" is a pattern.
		if strings.HasPrefix(sc.Text(), "#") {
			continue
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		exception := strings.HasPrefix(line, "!")
		if exception {
			line = strings.TrimSpace(line[1:])
			if line == "" {
				// Docker refuses it rather than reading it as "everything".
				return nil, fmt.Errorf(`.dockerignore line %d: illegal exclusion pattern: "!"`, n)
			}
		}
		// As in Docker, "/x" is "x", but "/" stays "/" and "." stays ".":
		// neither matches a context path, so they exclude nothing.
		line = path.Clean(filepath.ToSlash(line))
		if exception && line == "/" {
			// Docker cleans "!/" to "!" and refuses it like a bare "!".
			return nil, fmt.Errorf(`.dockerignore line %d: illegal exclusion pattern: "!"`, n)
		}
		if len(line) > 1 && line[0] == '/' {
			line = line[1:]
		}
		match, err := ignorePattern(line)
		if err != nil {
			return nil, fmt.Errorf(".dockerignore line %d: %w", n, err)
		}
		d.rules = append(d.rules, ignoreRule{match: match, exception: exception})
		d.hasExceptions = d.hasExceptions || exception
	}
	return d, sc.Err()
}

// excludes reports whether the slash-separated context path is ignored.
func (d *dockerignore) excludes(name string) bool {
	if d == nil {
		return false
	}
	excluded := false
	for _, r := range d.rules {
		if r.matches(name) {
			excluded = !r.exception
		}
	}
	return excluded
}

// matches is true when the pattern matches name or one of its parents
// ("vendor" excludes vendor/a/b).
func (r ignoreRule) matches(name string) bool {
	for p := name; ; {
		if r.match(p) {
			return true
		}
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			return false
		}
		p = p[:i]
	}
}

// ignorePattern compiles one cleaned .dockerignore pattern into a matcher for
// a slash-separated context path. It is a port of Pattern.compile and
// Pattern.match from github.com/moby/patternmatcher v0.6.0 (what the Docker
// CLI uses; Apache-2.0), with "/" as the separator, so a context holds what
// `docker build` would send:
//
//   - "*" is any run of characters but "/", "?" any one character but "/";
//   - "**" is any number of whole directories, wherever it stands: "a/**/b"
//     and "a**b" both match "a/b" and "a/x/b", and "a**b" does not match
//     "axb"; a trailing "**" matches anything;
//   - "[...]" is a regexp character class: "^" negates it and "!" is a
//     literal ("[!a]*" matches "abc" and "!x", not "bcd");
//   - "\" escapes the next character, as in a regexp;
//   - a pattern made only of literal characters matches its exact path; one
//     literal up to a trailing "**" matches by prefix, and one that is "**"
//     followed by literal characters matches by suffix ("**foo" matches
//     "barfoo").
//
// The pattern is checked first with path.Match, as Docker does with
// filepath.Match, so a malformed one ("[", "a\") is an error.
func ignorePattern(p string) (func(string) bool, error) {
	if _, err := path.Match(p, "."); err != nil {
		return nil, fmt.Errorf("pattern %q: %w", p, err)
	}
	const (
		exact = iota
		prefix
		suffix
		re
	)
	kind := exact
	var b strings.Builder
	b.WriteString("^")
	rs := []rune(p)
	for i := 0; i < len(rs); i++ {
		first := i == 0
		switch ch := rs[i]; {
		case ch == '*' && i+1 < len(rs) && rs[i+1] == '*':
			i++
			if i+1 < len(rs) && rs[i+1] == '/' {
				i++ // "**/" is "**"
			}
			switch {
			case i+1 < len(rs):
				b.WriteString("(.*/)?")
				kind = re
			case kind == exact:
				kind = prefix
			default:
				b.WriteString(".*")
				kind = re
			}
			if first {
				kind = suffix
			}
		case ch == '*':
			b.WriteString("[^/]*")
			kind = re
		case ch == '?':
			b.WriteString("[^/]")
			kind = re
		case strings.ContainsRune(`.+()|{}$`, ch):
			b.WriteString(`\` + string(ch))
		case ch == '\\':
			// path.Match has refused a trailing "\".
			i++
			b.WriteString(`\` + string(rs[i]))
			kind = re
		case ch == '[' || ch == ']':
			b.WriteRune(ch)
			kind = re
		default:
			b.WriteRune(ch)
		}
	}
	switch kind {
	case exact:
		return func(name string) bool { return name == p }, nil
	case prefix:
		lit := p[:len(p)-2]
		return func(name string) bool { return strings.HasPrefix(name, lit) }, nil
	case suffix:
		lit := p[2:]
		return func(name string) bool {
			return strings.HasSuffix(name, lit) || (strings.HasPrefix(lit, "/") && name == lit[1:])
		}, nil
	}
	rx, err := regexp.Compile(b.String() + "$")
	if err != nil {
		return nil, fmt.Errorf("pattern %q: %w", p, err)
	}
	return rx.MatchString, nil
}
