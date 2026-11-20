package contract

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/goccy/go-yaml/ast"
)

// checkDocument enforces what goccy's Strict mode does not: that the input is a
// single YAML document, and that every scalar has the JSON-schema type of the
// field it decodes into. Without it `container: "80"`, `summary: 123` or an
// environment value of null/true/1 would be silently coerced, though
// schemas/contract.schema.json rejects them. Values reached through an alias
// or a merge key (`<<`) are checked against the type at the place of use, as
// the schema sees the document with aliases and merges resolved. file and
// anchors come from checkAliases.
func checkDocument(file *ast.File, anchors map[string]ast.Node) error {
	var body ast.Node
	docs := 0
	for _, d := range file.Docs {
		if d == nil || d.Body == nil {
			continue // an empty document, e.g. a trailing `---`
		}
		docs++
		if body == nil {
			body = d.Body
		}
	}
	if docs > 1 {
		return se("(document)", "the file holds %d YAML documents; a contract must be a single document", docs)
	}
	if body == nil {
		return nil
	}
	return checker{anchors}.checkNodeType(body, reflect.TypeOf(rawContract{}), "")
}

// maxExpandedNodes bounds the size of a document with every alias expanded. A
// real contract has a few hundred nodes; nested aliases or merge keys can make
// a few hundred bytes expand exponentially (a "billion laughs" document), and
// goccy's decoder neither caps nor shares that expansion for merge keys.
const maxExpandedNodes = 100_000

// checkAliases runs before the decoder sees the document. It rejects aliases
// that do not refer to an earlier anchor (or refer to the node they sit in),
// anchors defined twice, and documents whose alias-expanded size exceeds
// maxExpandedNodes. It is linear in the size of the document. It returns the
// anchors of the first non-empty document, by name, for checkDocument.
//
// Requiring unique anchor names makes every alias resolve to one node no matter
// the order the decoder visits the document in, so the node checkDocument
// type-checks is the node the decoder decodes.
func checkAliases(file *ast.File) (map[string]ast.Node, error) {
	var first map[string]ast.Node
	total := 0
	for _, d := range file.Docs {
		if d == nil || d.Body == nil {
			continue
		}
		x := &expander{anchors: map[string]ast.Node{}, size: map[string]int{}, open: map[string]bool{}, total: total}
		if _, err := x.walk(d.Body); err != nil {
			return nil, err
		}
		total = x.total
		if first == nil {
			first = x.anchors
		}
	}
	return first, nil
}

type expander struct {
	anchors map[string]ast.Node // anchor name -> the node it marks
	size    map[string]int      // anchor name -> expanded size of its node
	open    map[string]bool     // anchors whose node is being walked
	total   int                 // expanded nodes counted so far
}

func lineOf(n ast.Node) string {
	if tk := n.GetToken(); tk != nil && tk.Position != nil {
		return fmt.Sprintf("line %d", tk.Position.Line)
	}
	return "(document)"
}

// walk returns the expanded size of n. Every node counts towards x.total, and
// an alias counts the expanded size of its anchor again, so x.total is the
// size of the fully expanded document.
func (x *expander) walk(n ast.Node) (int, error) {
	if n == nil {
		return 0, nil
	}
	count := func(k int) (int, error) {
		x.total += k
		if x.total > maxExpandedNodes {
			return 0, se(lineOf(n), "the document expands to more than %d nodes through aliases or merge keys", maxExpandedNodes)
		}
		return k, nil
	}
	switch v := n.(type) {
	case *ast.CommentGroupNode, *ast.CommentNode:
		return 0, nil
	case *ast.AnchorNode:
		name := v.Name.GetToken().Value
		if _, dup := x.anchors[name]; dup {
			return 0, se(lineOf(n), "anchor &%s is defined more than once; anchor names must be unique", name)
		}
		x.anchors[name] = v.Value
		x.open[name] = true
		k, err := x.walk(v.Value)
		if err != nil {
			return 0, err
		}
		delete(x.open, name)
		x.size[name] = k
		return k, nil
	case *ast.AliasNode:
		name := v.Value.GetToken().Value
		if x.open[name] {
			return 0, se(lineOf(n), "alias *%s refers to a node that contains it", name)
		}
		k, ok := x.size[name]
		if !ok {
			return 0, se(lineOf(n), "alias *%s does not refer to an earlier anchor", name)
		}
		return count(k)
	case *ast.TagNode:
		k, err := x.walk(v.Value)
		if err != nil {
			return 0, err
		}
		return k, nil
	}
	sum := 1
	var kids []ast.Node
	switch v := n.(type) {
	case *ast.MappingNode:
		for _, e := range v.Values {
			kids = append(kids, e)
		}
	case *ast.MappingValueNode:
		kids = []ast.Node{v.Key, v.Value}
	case *ast.MappingKeyNode:
		kids = []ast.Node{v.Value}
	case *ast.SequenceNode:
		kids = v.Values
	}
	if _, err := count(1); err != nil {
		return 0, err
	}
	for _, c := range kids {
		k, err := x.walk(c)
		if err != nil {
			return 0, err
		}
		sum += k
	}
	return sum, nil
}

// checker type-checks a document; anchors resolves aliases.
type checker struct {
	anchors map[string]ast.Node
}

var (
	commandType         = reflect.TypeOf(Command(nil))
	expectSanitizerType = reflect.TypeOf(ExpectSanitizer{})
)

// probeTypes are the verify-probe structs whose port, timeout and counts the
// schema bounds (port 1..65535, timeout > 0, attempts/min_hits/ms >= 1).
// Their Go fields are plain numbers where 0 means "the default", so an
// explicit `port: 0` or `timeout: 0` cannot be told apart from an absent key
// after decoding; checkNodeType rejects it here, where the key's presence is
// still visible.
var probeTypes = map[reflect.Type]bool{
	reflect.TypeOf(HTTPProbe{}):     true,
	reflect.TypeOf(ExecProbe{}):     true,
	reflect.TypeOf(TCPProbe{}):      true,
	reflect.TypeOf(NetProbe{}):      true,
	reflect.TypeOf(SequenceProbe{}): true,
	reflect.TypeOf(SequenceExec{}):  true,
	reflect.TypeOf(SleepStep{}):     true,
}

// positiveKeys are the probe keys checkPositive bounds.
var positiveKeys = map[string]bool{"port": true, "timeout": true, "attempts": true, "min_hits": true, "ms": true}

// checkPositive rejects an explicit non-positive probe port or timeout.
func (c checker) checkPositive(n ast.Node, key, loc string) error {
	var v float64
	switch x := c.unwrap(n).(type) {
	case *ast.IntegerNode:
		switch i := x.Value.(type) {
		case int64:
			v = float64(i)
		case uint64:
			v = float64(i)
		}
	case *ast.FloatNode:
		v = x.Value
	default:
		return nil // a type error is reported by checkNodeType
	}
	switch {
	case key == "port" && v < 1:
		return se(loc, "must be 1..65535")
	case key == "timeout" && v <= 0:
		return se(loc, "must be greater than 0")
	case (key == "attempts" || key == "min_hits" || key == "ms") && v < 1:
		return se(loc, "must be at least 1")
	}
	return nil
}

// nonEmptyLists are the list fields the schema declares with minItems: 1
// (metadata.class, service.ports, states.*.verify, net.steps), by key name.
var nonEmptyLists = map[string]bool{"class": true, "ports": true, "verify": true, "steps": true}

func lastSeg(loc string) string {
	if i := strings.LastIndexByte(loc, '/'); i >= 0 {
		return loc[i+1:]
	}
	return loc
}

// unwrap resolves anchors, tags and aliases to the node they stand for. An
// alias without an anchor (checkAliases rejects those) is returned as is.
func (c checker) unwrap(n ast.Node) ast.Node {
	for range maxExpandedNodes { // checkAliases rules out cycles; this is a backstop
		switch v := n.(type) {
		case *ast.AnchorNode:
			n = v.Value
		case *ast.TagNode:
			n = v.Value
		case *ast.AliasNode:
			target, ok := c.anchors[v.Value.GetToken().Value]
			if !ok {
				return n
			}
			n = target
		default:
			return n
		}
	}
	return n
}

func join(loc, key string) string {
	if loc == "" {
		return key
	}
	return loc + "/" + key
}

// describe names a node's YAML type for an error message.
func describe(n ast.Node) string {
	switch n.(type) {
	case *ast.NullNode:
		return "null"
	case *ast.BoolNode:
		return "a boolean"
	case *ast.IntegerNode:
		return "an integer"
	case *ast.FloatNode, *ast.InfinityNode, *ast.NanNode:
		return "a number"
	case *ast.StringNode, *ast.LiteralNode:
		return "a string"
	case *ast.SequenceNode:
		return "a list"
	case *ast.MappingNode, *ast.MappingValueNode:
		return "a mapping"
	}
	return "a " + strings.ToLower(n.Type().String())
}

func typeErr(loc, want string, n ast.Node) error {
	got := describe(n)
	if s, ok := n.(ast.ScalarNode); ok {
		if _, isNull := n.(*ast.NullNode); !isNull {
			if isString(n) {
				got = fmt.Sprintf("%s (%q)", got, fmt.Sprint(s.GetValue()))
			} else {
				got = fmt.Sprintf("%s (%v)", got, s.GetValue())
			}
		}
	}
	return se(loc, "must be %s, got %s", want, got)
}

func mappingEntries(n ast.Node) ([]*ast.MappingValueNode, bool) {
	switch v := n.(type) {
	case *ast.MappingNode:
		return v.Values, true
	case *ast.MappingValueNode:
		return []*ast.MappingValueNode{v}, true
	}
	return nil, false
}

func isString(n ast.Node) bool {
	switch n.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		return true
	}
	return false
}

// checkNodeType checks node n against Go type t (mirroring the schema type the
// field is declared with).
func (c checker) checkNodeType(n ast.Node, t reflect.Type, loc string) error {
	n = c.unwrap(n)
	if n == nil {
		return nil
	}
	if a, ok := n.(*ast.AliasNode); ok {
		return se(loc, "alias *%s does not refer to an anchor", a.Value.GetToken().Value)
	}
	if t == commandType {
		if isString(n) {
			return nil
		}
		if _, ok := n.(*ast.SequenceNode); !ok {
			return typeErr(loc, "a string or a list of strings", n)
		}
		return c.checkNodeType(n, reflect.TypeOf([]string(nil)), loc)
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == expectSanitizerType {
		// The scalar none (its value is checked by the decoder) or a
		// { kind, frame } mapping.
		if isString(n) {
			return nil
		}
		if _, ok := mappingEntries(n); !ok {
			return typeErr(loc, "none or a mapping", n)
		}
		return c.checkNodeType(n, reflect.TypeOf(rawExpectSanitizer{}), loc)
	}
	switch t.Kind() {
	case reflect.String:
		if !isString(n) {
			return typeErr(loc, "a string", n)
		}
	case reflect.Int, reflect.Int64:
		if _, ok := n.(*ast.IntegerNode); !ok {
			return typeErr(loc, "an integer", n)
		}
	case reflect.Float64:
		switch n.(type) {
		case *ast.IntegerNode, *ast.FloatNode:
		default:
			return typeErr(loc, "a number", n)
		}
	case reflect.Bool:
		if _, ok := n.(*ast.BoolNode); !ok {
			return typeErr(loc, "a boolean", n)
		}
	case reflect.Slice:
		seq, ok := n.(*ast.SequenceNode)
		if !ok {
			return typeErr(loc, "a list", n)
		}
		if len(seq.Values) == 0 && nonEmptyLists[lastSeg(loc)] {
			return se(loc, "must not be empty")
		}
		for i, v := range seq.Values {
			if err := c.checkNodeType(v, t.Elem(), join(loc, fmt.Sprint(i))); err != nil {
				return err
			}
		}
	case reflect.Map:
		entries, ok := mappingEntries(n)
		if !ok {
			return typeErr(loc, "a mapping", n)
		}
		for _, e := range entries {
			if e.Key.IsMergeKey() {
				if err := c.checkMerge(e.Value, t, loc); err != nil {
					return err
				}
				continue
			}
			if err := c.checkNodeType(e.Value, t.Elem(), join(loc, c.keyName(e.Key))); err != nil {
				return err
			}
		}
	case reflect.Struct:
		entries, ok := mappingEntries(n)
		if !ok {
			return typeErr(loc, "a mapping", n)
		}
		for _, e := range entries {
			if e.Key.IsMergeKey() {
				if err := c.checkMerge(e.Value, t, loc); err != nil {
					return err
				}
				continue
			}
			key := c.keyName(e.Key)
			f, ok := fieldByYAMLName(t, key)
			if !ok {
				// The strict decoder rejects these first; this keeps keys
				// that arrive through a merge from slipping past either.
				return se(join(loc, key), "unknown field %q", key)
			}
			if err := c.checkNodeType(e.Value, f.Type, join(loc, key)); err != nil {
				return err
			}
			if probeTypes[t] && positiveKeys[key] {
				if err := c.checkPositive(e.Value, key, join(loc, key)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// checkMerge checks the value of a merge key (`<<: *base`, `<<: {...}` or
// `<<: [*a, *b]`) inside a mapping of type t (a struct or a map): each merged
// entry must suit t exactly as if it had been written inline. Every merged
// value is checked, including one the mapping overrides, so no path through
// the merge picks up a wrongly typed value.
func (c checker) checkMerge(v ast.Node, t reflect.Type, loc string) error {
	sources := []ast.Node{v}
	if seq, ok := c.unwrap(v).(*ast.SequenceNode); ok {
		sources = seq.Values
	}
	for _, src := range sources {
		m := c.unwrap(src)
		if _, ok := mappingEntries(m); !ok {
			return typeErr(join(loc, "<<"), "a mapping or a list of mappings", m)
		}
		if err := c.checkNodeType(m, t, loc); err != nil {
			return err
		}
	}
	return nil
}

// fieldByYAMLName finds the field a YAML key decodes into, looking through
// embedded structs tagged `yaml:",inline"`.
func fieldByYAMLName(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if f.Anonymous && tag == "" && opts == "inline" && f.Type.Kind() == reflect.Struct {
			if inner, ok := fieldByYAMLName(f.Type, name); ok {
				return inner, true
			}
			continue
		}
		if tag == name && tag != "-" {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

func (c checker) keyName(k ast.MapKeyNode) string {
	if s, ok := c.unwrap(k).(ast.ScalarNode); ok {
		return fmt.Sprint(s.GetValue())
	}
	return k.String()
}
