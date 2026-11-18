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
	re        *regexp.Regexp
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
		line = path.Clean(filepath.ToSlash(line))
		line = strings.TrimPrefix(line, "/")
		if line == "" || line == "." {
			// "/" or "." matches the whole context.
			line = "**"
		}
		re, err := ignorePattern(line)
		if err != nil {
			return nil, fmt.Errorf(".dockerignore line %d: %w", n, err)
		}
		d.rules = append(d.rules, ignoreRule{re: re, exception: exception})
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
		if r.re.MatchString(p) {
			return true
		}
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			return false
		}
		p = p[:i]
	}
}

// ignorePattern compiles a .dockerignore pattern: filepath.Match syntax per
// path segment ("*", "?", "[...]", "\\" escapes) plus "**" for any number of
// segments.
func ignorePattern(p string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch c {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				i++
				switch {
				case i+1 < len(p) && p[i+1] == '/':
					i++
					b.WriteString("(?:.*/)?") // "**/" : zero or more directories
				default:
					b.WriteString(".*")
				}
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		case '[':
			j := i + 1
			if j < len(p) && (p[j] == '!' || p[j] == '^') {
				j++
			}
			if j < len(p) && p[j] == ']' {
				j++
			}
			for j < len(p) && p[j] != ']' {
				if p[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(p) {
				return nil, fmt.Errorf("pattern %q: unterminated [", p)
			}
			class := p[i+1 : j]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + class + "]")
			i = j
		case '\\':
			if i+1 >= len(p) {
				return nil, fmt.Errorf("pattern %q: trailing \\", p)
			}
			i++
			b.WriteString(regexp.QuoteMeta(string(p[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("pattern %q: %w", p, err)
	}
	return re, nil
}
