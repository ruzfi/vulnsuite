package contract

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// checkDocument enforces what goccy's Strict mode does not: that the input is a
// single YAML document, and that every scalar has the JSON-schema type of the
// field it decodes into. Without it `container: "80"`, `summary: 123` or an
// environment value of null/true/1 would be silently coerced, though
// schemas/contract.schema.json rejects them.
func checkDocument(data []byte) error {
	file, err := parser.ParseBytes(data, 0)
	if err != nil {
		return err // Parse reports syntax errors from the decoder first
	}
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
	return checkNodeType(body, reflect.TypeOf(rawContract{}), "")
}

var commandType = reflect.TypeOf(Command(nil))

// probeTypes are the verify-probe structs whose port and timeout the schema
// bounds (port 1..65535, timeout > 0). Their Go fields are plain numbers where
// 0 means "the default", so an explicit `port: 0` or `timeout: 0` cannot be
// told apart from an absent key after decoding; checkNodeType rejects it here,
// where the key's presence is still visible.
var probeTypes = map[reflect.Type]bool{
	reflect.TypeOf(HTTPProbe{}): true,
	reflect.TypeOf(ExecProbe{}): true,
	reflect.TypeOf(TCPProbe{}):  true,
	reflect.TypeOf(NetProbe{}):  true,
}

// checkPositive rejects an explicit non-positive probe port or timeout.
func checkPositive(n ast.Node, key, loc string) error {
	var v float64
	switch x := unwrap(n).(type) {
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

// unwrap resolves anchors and tags to the node they decorate. Aliases are
// returned as is (their target was checked where it was defined).
func unwrap(n ast.Node) ast.Node {
	for {
		switch v := n.(type) {
		case *ast.AnchorNode:
			n = v.Value
		case *ast.TagNode:
			n = v.Value
		default:
			return n
		}
	}
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
func checkNodeType(n ast.Node, t reflect.Type, loc string) error {
	n = unwrap(n)
	if _, ok := n.(*ast.AliasNode); ok || n == nil {
		return nil
	}
	if t == commandType {
		if isString(n) {
			return nil
		}
		if _, ok := n.(*ast.SequenceNode); !ok {
			return typeErr(loc, "a string or a list of strings", n)
		}
		return checkNodeType(n, reflect.TypeOf([]string(nil)), loc)
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
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
			if err := checkNodeType(v, t.Elem(), join(loc, fmt.Sprint(i))); err != nil {
				return err
			}
		}
	case reflect.Map:
		entries, ok := mappingEntries(n)
		if !ok {
			return typeErr(loc, "a mapping", n)
		}
		for _, e := range entries {
			if _, merge := e.Key.(*ast.MergeKeyNode); merge {
				continue
			}
			if err := checkNodeType(e.Value, t.Elem(), join(loc, keyName(e.Key))); err != nil {
				return err
			}
		}
	case reflect.Struct:
		entries, ok := mappingEntries(n)
		if !ok {
			return typeErr(loc, "a mapping", n)
		}
		for _, e := range entries {
			if _, merge := e.Key.(*ast.MergeKeyNode); merge {
				continue
			}
			key := keyName(e.Key)
			f, ok := fieldByYAMLName(t, key)
			if !ok {
				continue // unknown keys are rejected by the strict decoder
			}
			if err := checkNodeType(e.Value, f.Type, join(loc, key)); err != nil {
				return err
			}
			if probeTypes[t] && (key == "port" || key == "timeout") {
				if err := checkPositive(e.Value, key, join(loc, key)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func fieldByYAMLName(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if tag == name {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

func keyName(k ast.MapKeyNode) string {
	if s, ok := unwrap(k).(ast.ScalarNode); ok {
		return fmt.Sprint(s.GetValue())
	}
	return k.String()
}
