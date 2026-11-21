package contract

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// This file checks that schemas/contract.schema.json and the Go decoder
// (Parse) agree on every contract in testdata: each good contract must pass
// both, each bad one must fail both. The module has no JSON-schema validator
// and the project takes no new dependencies, so schemaCheck below is a small
// validator for exactly the draft 2020-12 keywords the schema uses; any other
// keyword fails the test (TestSchemaKeywordsSupported), so the checker cannot
// silently ignore a rule that is added to the schema later.

// supportedKeywords are the keywords schemaCheck implements, plus annotations
// that have no effect on validation.
var supportedKeywords = map[string]bool{
	"type": true, "enum": true, "const": true,
	"properties": true, "additionalProperties": true, "required": true,
	"minProperties": true, "maxProperties": true,
	"items": true, "minItems": true, "uniqueItems": true,
	"pattern": true, "minLength": true, "maxLength": true, "propertyNames": true,
	"minimum": true, "maximum": true, "exclusiveMinimum": true,
	"oneOf": true, "not": true, "if": true, "then": true, "$ref": true, "$defs": true,
	// annotations
	"$schema": true, "$id": true, "title": true, "description": true,
}

// decoderOnly lists the bad testdata that the schema cannot reject, each with
// the reason. These are rules of the YAML layer or cross-field rules JSON
// Schema has no keyword for; the test asserts the schema really does accept
// them (so the list cannot go stale) and that the decoder rejects them.
var decoderOnly = map[string]string{
	"multi-document.yaml": "a stream of several YAML documents is a YAML-level error; the schema sees only one document",
	"port-float.yaml": "80.0 is an integer to JSON Schema (draft 2020-12 ignores a zero fraction), " +
		"but the decoder requires a YAML integer, as `container: 80.0` is almost certainly a mistake",
	"sidecar-duplicate.yaml": "uniqueItems compares whole objects; sidecar names being unique cannot be expressed",
	"disclosed-feb-30.yaml": "the pattern bounds month 01-12 and day 01-31, but whether a day exists in its month " +
		"(Feb 30, Apr 31, Feb 29 outside a leap year) needs a calendar; the decoder parses the date",
	"verified-on-bad-date.yaml": "as for disclosed-feb-30.yaml: whether a day exists in its month needs a calendar",
	"verified-on-duplicate-host.yaml": "uniqueItems compares whole runs; one run per host and platform compares two " +
		"of their fields, which JSON Schema has no keyword for",
	"sequence-min-hits-over-attempts.yaml": "min_hits must not exceed attempts, a comparison of two sibling values " +
		"that JSON Schema has no keyword for",
}

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", "contract.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSchemaKeywordsSupported(t *testing.T) {
	var walk func(node any, loc string, inProps bool)
	walk = func(node any, loc string, inProps bool) {
		switch n := node.(type) {
		case map[string]any:
			for k, v := range n {
				switch {
				case inProps:
					// keys of properties / $defs are names, not keywords
					walk(v, loc+"/"+k, false)
					continue
				case !supportedKeywords[k]:
					t.Errorf("%s: keyword %q is not implemented by the test's schema checker; add it to schemaCheck", loc, k)
				}
				walk(v, loc+"/"+k, k == "properties" || k == "$defs")
			}
		case []any:
			for i, v := range n {
				walk(v, fmt.Sprintf("%s/%d", loc, i), false)
			}
		}
	}
	walk(loadSchema(t), "#", false)
}

// testdataContracts returns every contract in testdata: pkg/contract's good
// and bad sets plus the template fixtures, which must all be valid.
func testdataContracts(t *testing.T) (good, bad []string) {
	t.Helper()
	good, _ = filepath.Glob("testdata/good/*.yaml")
	bad, _ = filepath.Glob("testdata/bad/*.yaml")
	root := filepath.Join("..", "..", "testdata", "templates")
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == "contract.yaml" {
			good = append(good, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(good) == 0 || len(bad) == 0 {
		t.Fatal("no testdata contracts")
	}
	return good, bad
}

func TestSchemaAndDecoderAgree(t *testing.T) {
	schema := loadSchema(t)
	good, bad := testdataContracts(t)
	check := func(path string) (schemaErrs []string, decodeErr error) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		_, decodeErr = Parse(data)
		var doc any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return []string{"yaml: " + err.Error()}, decodeErr
		}
		return schemaCheck(schema, schema, jsonValue(doc), "#"), decodeErr
	}
	for _, f := range good {
		t.Run("good/"+f, func(t *testing.T) {
			serrs, derr := check(f)
			if derr != nil {
				t.Errorf("decoder rejects a good contract: %v", derr)
			}
			if len(serrs) > 0 {
				t.Errorf("schema rejects a good contract:\n  %s", strings.Join(serrs, "\n  "))
			}
		})
	}
	seenOnly := map[string]bool{}
	for _, f := range bad {
		name := filepath.Base(f)
		t.Run("bad/"+name, func(t *testing.T) {
			serrs, derr := check(f)
			if derr == nil {
				t.Errorf("decoder accepts a bad contract (schema says: %v)", serrs)
			}
			if why, ok := decoderOnly[name]; ok {
				seenOnly[name] = true
				if len(serrs) > 0 {
					t.Errorf("listed as decoder-only (%s) but the schema rejects it too: %v; drop it from decoderOnly", why, serrs)
				}
				return
			}
			if len(serrs) == 0 {
				t.Errorf("schema accepts a contract the decoder rejects (%v): the schema and pkg/contract have drifted", derr)
			}
		})
	}
	for name := range decoderOnly {
		if !seenOnly[name] {
			t.Errorf("decoderOnly names %s, which is not in testdata/bad", name)
		}
	}
}

// TestSchemaChecker pins the checker's own behaviour on the keywords it
// implements, so an agreement above is not an artefact of a lax checker.
func TestSchemaChecker(t *testing.T) {
	root := map[string]any{"$defs": map[string]any{"n": map[string]any{"type": "integer", "minimum": 1.0}}}
	cases := []struct {
		schema string
		value  any
		ok     bool
	}{
		{`{"type":"integer"}`, 3.0, true},
		{`{"type":"integer"}`, 3.5, false},
		{`{"type":"integer"}`, "3", false},
		{`{"type":["string","array"],"items":{"type":"string"}}`, []any{"a", 1.0}, false},
		{`{"type":["string","array"]}`, "a", true},
		{`{"enum":["a","b"]}`, "c", false},
		{`{"const":"x"}`, "x", true},
		{`{"type":"object","required":["a"]}`, map[string]any{}, false},
		{`{"type":"object","additionalProperties":false,"properties":{"a":{}}}`, map[string]any{"b": 1.0}, false},
		{`{"type":"object","additionalProperties":{"type":"string"}}`, map[string]any{"b": true}, false},
		{`{"minProperties":1,"maxProperties":1}`, map[string]any{"a": 1.0, "b": 1.0}, false},
		{`{"minItems":1}`, []any{}, false},
		{`{"uniqueItems":true}`, []any{"a", "a"}, false},
		{`{"pattern":"^a+$"}`, "aab", false},
		{`{"minLength":3,"maxLength":4}`, "ab", false},
		{`{"maximum":10}`, 11.0, false},
		{`{"exclusiveMinimum":0}`, 0.0, false},
		{`{"exclusiveMinimum":0}`, 0.5, true},
		{`{"oneOf":[{"const":1},{"type":"number"}]}`, 1.0, false},
		{`{"oneOf":[{"const":1},{"type":"string"}]}`, 1.0, true},
		{`{"not":{"enum":["a"]}}`, "a", false},
		{`{"not":{"enum":["a"]}}`, "b", true},
		{`{"if":{"const":1},"then":{"type":"string"}}`, 1.0, false},
		{`{"if":{"const":1},"then":{"type":"string"}}`, 2.0, true},
		{`{"$ref":"#/$defs/n"}`, 0.0, false},
		{`{"$ref":"#/$defs/n"}`, 2.0, true},
		// a leading negative lookahead, as the template-path patterns use
		{`{"pattern":"^(?![/\\\\])(?!(.*/)?\\.\\.(/|$))[a-z./]+$"}`, "a/b", true},
		{`{"pattern":"^(?![/\\\\])(?!(.*/)?\\.\\.(/|$))[a-z./]+$"}`, "a/..b", true},
		{`{"pattern":"^(?![/\\\\])(?!(.*/)?\\.\\.(/|$))[a-z./]+$"}`, "/a", false},
		{`{"pattern":"^(?![/\\\\])(?!(.*/)?\\.\\.(/|$))[a-z./]+$"}`, "../a", false},
		{`{"pattern":"^(?![/\\\\])(?!(.*/)?\\.\\.(/|$))[a-z./]+$"}`, "a/../b", false},
		{`{"pattern":"^(?![/\\\\])(?!(.*/)?\\.\\.(/|$))[a-z./]+$"}`, "a/..", false},
	}
	for _, tc := range cases {
		var s map[string]any
		if err := json.Unmarshal([]byte(tc.schema), &s); err != nil {
			t.Fatal(err)
		}
		errs := schemaCheck(root, s, tc.value, "#")
		if (len(errs) == 0) != tc.ok {
			t.Errorf("%s on %#v: errors %v, want ok=%v", tc.schema, tc.value, errs, tc.ok)
		}
	}
}

// jsonValue converts a decoded YAML value to the JSON data model the schema is
// written against: objects with string keys, arrays, float64 numbers.
func jsonValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = jsonValue(e)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[fmt.Sprint(k)] = jsonValue(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = jsonValue(e)
		}
		return out
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case uint64:
		return float64(x)
	case float32:
		return float64(x)
	}
	return v
}

func jsonType(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64:
		if x == math.Trunc(x) && !math.IsInf(x, 0) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("unknown(%T)", v)
}

func typeMatches(want string, v any) bool {
	got := jsonType(v)
	return got == want || (want == "number" && got == "integer")
}

func num(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

// schemaCheck validates v against schema s (root resolves $ref) and returns
// every violation, as "location: message".
func schemaCheck(root, s map[string]any, v any, loc string) []string {
	var errs []string
	fail := func(format string, args ...any) {
		errs = append(errs, loc+": "+fmt.Sprintf(format, args...))
	}
	if ref, ok := s["$ref"].(string); ok {
		target := resolveRef(root, ref)
		if target == nil {
			fail("unresolvable $ref %s", ref)
		} else {
			errs = append(errs, schemaCheck(root, target, v, loc)...)
		}
	}
	switch tv := s["type"].(type) {
	case string:
		if !typeMatches(tv, v) {
			fail("want type %s, got %s", tv, jsonType(v))
			return errs
		}
	case []any:
		ok := false
		for _, t := range tv {
			if typeMatches(t.(string), v) {
				ok = true
			}
		}
		if !ok {
			fail("want type %v, got %s", tv, jsonType(v))
			return errs
		}
	}
	if e, ok := s["enum"].([]any); ok {
		found := false
		for _, c := range e {
			if reflect.DeepEqual(c, v) {
				found = true
			}
		}
		if !found {
			fail("%v is not one of %v", v, e)
		}
	}
	if c, ok := s["const"]; ok && !reflect.DeepEqual(c, v) {
		fail("%v is not %v", v, c)
	}
	if one, ok := s["oneOf"].([]any); ok {
		n := 0
		for _, sub := range one {
			if len(schemaCheck(root, sub.(map[string]any), v, loc)) == 0 {
				n++
			}
		}
		if n != 1 {
			fail("matches %d of oneOf's %d schemas, want exactly 1", n, len(one))
		}
	}
	if not, ok := s["not"].(map[string]any); ok && len(schemaCheck(root, not, v, loc)) == 0 {
		fail("matches a schema it must not match")
	}
	if cond, ok := s["if"].(map[string]any); ok && len(schemaCheck(root, cond, v, loc)) == 0 {
		if then, ok := s["then"].(map[string]any); ok {
			errs = append(errs, schemaCheck(root, then, v, loc)...)
		}
	}
	switch x := v.(type) {
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		for _, r := range asList(s["required"]) {
			if _, ok := x[r.(string)]; !ok {
				fail("missing required property %q", r)
			}
		}
		if n, ok := num(s["minProperties"]); ok && float64(len(x)) < n {
			fail("has %d properties, want at least %v", len(x), n)
		}
		if n, ok := num(s["maxProperties"]); ok && float64(len(x)) > n {
			fail("has %d properties, want at most %v", len(x), n)
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if pn, ok := s["propertyNames"].(map[string]any); ok {
			for _, k := range keys {
				errs = append(errs, schemaCheck(root, pn, k, loc+"/"+k+" (name)")...)
			}
		}
		for _, k := range keys {
			if ps, ok := props[k].(map[string]any); ok {
				errs = append(errs, schemaCheck(root, ps, x[k], loc+"/"+k)...)
				continue
			}
			switch ap := s["additionalProperties"].(type) {
			case bool:
				if !ap {
					errs = append(errs, loc+"/"+k+": additional property not allowed")
				}
			case map[string]any:
				errs = append(errs, schemaCheck(root, ap, x[k], loc+"/"+k)...)
			}
		}
	case []any:
		if n, ok := num(s["minItems"]); ok && float64(len(x)) < n {
			fail("has %d items, want at least %v", len(x), n)
		}
		if u, _ := s["uniqueItems"].(bool); u {
			for i := range x {
				for j := i + 1; j < len(x); j++ {
					if reflect.DeepEqual(x[i], x[j]) {
						fail("items %d and %d are equal", i, j)
					}
				}
			}
		}
		if is, ok := s["items"].(map[string]any); ok {
			for i, e := range x {
				errs = append(errs, schemaCheck(root, is, e, fmt.Sprintf("%s/%d", loc, i))...)
			}
		}
	case string:
		if p, ok := s["pattern"].(string); ok {
			if match := schemaPattern(p); match != nil && !match(x) {
				fail("%q does not match %s", x, p)
			}
		}
		n := float64(len([]rune(x)))
		if m, ok := num(s["minLength"]); ok && n < m {
			fail("shorter than %v", m)
		}
		if m, ok := num(s["maxLength"]); ok && n > m {
			fail("longer than %v", m)
		}
	case float64:
		if m, ok := num(s["minimum"]); ok && x < m {
			fail("%v is less than %v", x, m)
		}
		if m, ok := num(s["maximum"]); ok && x > m {
			fail("%v is greater than %v", x, m)
		}
		if m, ok := num(s["exclusiveMinimum"]); ok && x <= m {
			fail("%v is not greater than %v", x, m)
		}
	}
	return errs
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// resolveRef resolves a local JSON pointer ("#/$defs/state").
func resolveRef(root map[string]any, ref string) map[string]any {
	ptr, ok := strings.CutPrefix(ref, "#/")
	if !ok {
		return nil
	}
	var cur any = root
	for _, seg := range strings.Split(ptr, "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[seg]
	}
	m, _ := cur.(map[string]any)
	return m
}

// TestSchemaPatternsCompile makes sure the checker enforces every pattern in
// the schema rather than skipping one it cannot compile.
func TestSchemaPatternsCompile(t *testing.T) {
	var walk func(node any, loc string, inProps bool)
	walk = func(node any, loc string, inProps bool) {
		switch n := node.(type) {
		case map[string]any:
			for k, v := range n {
				if p, ok := v.(string); ok && k == "pattern" && !inProps && schemaPattern(p) == nil {
					t.Errorf("%s: the checker cannot compile pattern %q", loc, p)
				}
				walk(v, loc+"/"+k, !inProps && (k == "properties" || k == "$defs"))
			}
		case []any:
			for i, v := range n {
				walk(v, fmt.Sprintf("%s/%d", loc, i), false)
			}
		}
	}
	walk(loadSchema(t), "#", false)
}

// schemaPattern compiles a JSON-Schema (ECMA-262) pattern with Go's regexp,
// rewriting the \uXXXX escapes ECMA-262 allows into Go's \x{XXXX}. RE2 has
// no lookaheads, which the template-path patterns open with: a pattern of the
// form ^(?!A)(?!B)...REST is matched as "REST matches from the start, and
// neither A nor B matches a prefix", which is what a negative lookahead at
// the start of the string means. It returns nil for any other pattern RE2
// cannot express, which fails TestSchemaPatternsCompile.
func schemaPattern(p string) func(string) bool {
	compile := func(p string) *regexp.Regexp {
		re, err := regexp.Compile(ecmaUnicodeEscape.ReplaceAllString(p, `\x{$1}`))
		if err != nil {
			return nil
		}
		return re
	}
	if re := compile(p); re != nil {
		return re.MatchString
	}
	rest, ok := strings.CutPrefix(p, "^")
	if !ok {
		return nil
	}
	var not []*regexp.Regexp
	for strings.HasPrefix(rest, "(?!") {
		end := groupEnd(rest)
		if end < 0 {
			return nil
		}
		re := compile("^(?:" + rest[len("(?!"):end] + ")")
		if re == nil {
			return nil
		}
		not = append(not, re)
		rest = rest[end+1:]
	}
	re := compile("^(?:" + rest + ")")
	if len(not) == 0 || re == nil {
		return nil
	}
	return func(s string) bool {
		for _, n := range not {
			if n.MatchString(s) {
				return false
			}
		}
		return re.MatchString(s)
	}
}

// groupEnd returns the index of the ")" closing the group p opens with,
// skipping escapes and character classes, or -1.
func groupEnd(p string) int {
	depth, class := 0, false
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '\\':
			i++
		case class:
			class = c != ']'
		case c == '[':
			class = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

var ecmaUnicodeEscape = regexp.MustCompile(`\\u([0-9A-Fa-f]{4})`)
