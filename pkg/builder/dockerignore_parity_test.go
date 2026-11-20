package builder

import (
	"runtime"
	"strings"
	"testing"
)

// TestDockerignoreMatchesPatternmatcher compares parseDockerignore with the
// Docker CLI's own matcher on a fixed set of files and paths (#93 item 5). The
// table was generated with github.com/moby/patternmatcher v0.6.0 (ignorefile.ReadAll,
// then New and MatchesOrParentMatches on each path) in a scratch module, so
// the project takes no dependency on it. Some rows pin Docker's quirks rather
// than intent ("\d" is a regexp class, "**foo" matches "barfoo"); matching
// them is the point, as the context must be what `docker build` would send.
func TestDockerignoreMatchesPatternmatcher(t *testing.T) {
	for _, tc := range patternmatcherCases {
		if runtime.GOOS == "windows" && strings.Contains(tc.file, `\`) {
			continue // "\" is a path separator there, not an escape
		}
		d, err := parseDockerignore([]byte(tc.file + "\n"))
		if tc.err {
			if err == nil {
				t.Errorf("%q: Docker refuses it, parseDockerignore accepted it", tc.file)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.file, err)
			continue
		}
		want := map[string]bool{}
		for _, p := range tc.excluded {
			want[p] = true
		}
		for _, p := range dockerignorePaths {
			if got := d.excludes(p); got != want[p] {
				t.Errorf("%q, path %q: excluded=%v, Docker says %v", tc.file, p, got, want[p])
			}
		}
	}
}

var patternmatcherCases = []struct {
	file     string
	excluded []string // nil: none; the rest of dockerignorePaths are sent
	err      bool
}{
	{"/", nil, false},
	{".", nil, false},
	{"./", nil, false},
	{"/.", nil, false},
	{"!/\n", nil, true},
	{"*\n!/", nil, true},
	{"*\n!.", dockerignorePaths, false},
	{"[!a]*", []string{"abc", "!x", "axb", "ab", "a/b", "ax/b", "a/x/b", "a/x/b/c", "a", "a/x", "a/xy", "abc/main.go", "a*b", "aXb", "a.b", "a(b)", "a{b}", "a|b", "ab", "a$b", "a^b", "a^c", "abs", "abd", "acd", "aed", "an", "a\n", "a\\", "a-]x", "a]x"}, false},
	{"[^a]*", []string{"bcd", "!x", "]x", "-x", "foo", "barfoo", "x/foo", "x/barfoo", "main.go", "x/main.go", "x", "x/q/y", "x/q", "q/x", "q/x/r", "x/y/z", "x.y", "xzy", "x+y", "xxy", "dir", "dir/f", "d", "1", "spaced", "# not a comment", "\\x"}, false},
	{"[a-c]?", []string{"ab", "ax/b", "ab", "an", "a\n", "a\\"}, false},
	{"a[bc]d", []string{"abd", "acd"}, false},
	{"[]a]*", nil, true},
	{"[a-]*", nil, true},
	{"a**b", []string{"ab", "a/b", "ax/b", "a/x/b", "a/x/b/c", "ab"}, false},
	{"a**", []string{"abc", "axb", "ab", "a/b", "ax/b", "a/x/b", "a/x/b/c", "a", "a/x", "a/xy", "abc/main.go", "a*b", "aXb", "a.b", "a(b)", "a{b}", "a|b", "ab", "a$b", "a^b", "a^c", "abs", "abd", "acd", "aed", "an", "a\n", "a\\", "a-]x", "a]x"}, false},
	{"**", dockerignorePaths, false},
	{"**/", dockerignorePaths, false},
	{"**foo", []string{"foo", "barfoo", "x/foo", "x/barfoo"}, false},
	{"**/foo", []string{"foo", "x/foo"}, false},
	{"**/*.go", []string{"main.go", "x/main.go", "abc/main.go"}, false},
	{"**/x/**", []string{"a/x/b", "a/x/b/c", "x/foo", "x/barfoo", "x/main.go", "x/q/y", "x/q", "q/x/r", "x/y/z"}, false},
	{"a/**", []string{"a/b", "a/x/b", "a/x/b/c", "a/x", "a/xy"}, false},
	{"a/**/b", []string{"a/b", "a/x/b", "a/x/b/c"}, false},
	{"a/**/b/**", []string{"a/x/b/c"}, false},
	{"x/*/y", []string{"x/q/y"}, false},
	{"*/x", []string{"a/x/b", "a/x/b/c", "a/x", "q/x", "q/x/r"}, false},
	{"*.go", []string{"main.go"}, false},
	{"a?c", []string{"abc", "abc/main.go", "a^c"}, false},
	{"?", []string{"a/b", "a/x/b", "a/x/b/c", "x/foo", "x/barfoo", "a", "a/x", "a/xy", "x/main.go", "x", "x/q/y", "x/q", "q/x", "q/x/r", "x/y/z", "d", "1"}, false},
	{"a\\*b", []string{"a*b"}, false},
	{"a\\.b", []string{"a.b"}, false},
	{"x.y", []string{"x.y"}, false},
	{"x+y", []string{"x+y"}, false},
	{"a(b)", []string{"a(b)"}, false},
	{"a{b}", []string{"a{b}"}, false},
	{"a|b", []string{"a|b"}, false},
	{"a$b", []string{"a$b"}, false},
	{"a^b", []string{"a^b"}, false},
	{"a^*", nil, false},
	{"\\d", []string{"1"}, false},
	{"a\\n", []string{"a\n"}, false},
	{"dir/", []string{"dir", "dir/f"}, false},
	{"/abs", []string{"abs"}, false},
	{"//abs", []string{"abs"}, false},
	{"a/../abs", []string{"abs"}, false},
	{"  spaced  ", []string{"spaced"}, false},
	{"  # not a comment", []string{"# not a comment"}, false},
	{"#comment\nabc", []string{"abc", "abc/main.go"}, false},
	{"*\n!abc", []string{"bcd", "!x", "]x", "-x", "axb", "ab", "a/b", "ax/b", "a/x/b", "a/x/b/c", "foo", "barfoo", "x/foo", "x/barfoo", "a", "a/x", "a/xy", "main.go", "x/main.go", "x", "x/q/y", "x/q", "q/x", "q/x/r", "x/y/z", "a*b", "aXb", "a.b", "x.y", "xzy", "x+y", "xxy", "a(b)", "a{b}", "a|b", "ab", "a$b", "a^b", "a^c", "dir", "dir/f", "abs", "abd", "acd", "aed", "d", "1", "an", "a\n", "spaced", "# not a comment", "a\\", "a-]x", "a]x", "\\x"}, false},
	{"*\n!a*\nabd", []string{"bcd", "!x", "]x", "-x", "foo", "barfoo", "x/foo", "x/barfoo", "main.go", "x/main.go", "x", "x/q/y", "x/q", "q/x", "q/x/r", "x/y/z", "x.y", "xzy", "x+y", "xxy", "dir", "dir/f", "abd", "d", "1", "spaced", "# not a comment", "\\x"}, false},
	{"a\n!a/x", []string{"a/b", "a", "a/xy"}, false},
	{"a/x\n!a", nil, false},
	{"[", nil, true},
	{"a[b", nil, true},
	{"a\\", nil, true},
	{"!", nil, true},
	{"!\n", nil, true},
	{"[a-\\]]x", nil, true},
}

var dockerignorePaths = []string{"abc", "bcd", "!x", "]x", "-x", "axb", "ab", "a/b", "ax/b", "a/x/b", "a/x/b/c", "foo", "barfoo", "x/foo", "x/barfoo", "a", "a/x", "a/xy", "main.go", "x/main.go", "abc/main.go", "x", "x/q/y", "x/q", "q/x", "q/x/r", "x/y/z", "a*b", "aXb", "a.b", "x.y", "xzy", "x+y", "xxy", "a(b)", "a{b}", "a|b", "ab", "a$b", "a^b", "a^c", "dir", "dir/f", "abs", "abd", "acd", "aed", "d", "1", "an", "a\n", "spaced", "# not a comment", "a\\", "a-]x", "a]x", "\\x"}
