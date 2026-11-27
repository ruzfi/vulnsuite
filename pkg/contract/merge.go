package contract

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
)

// premerge resolves every merge key (`<<: *base`, `<<: {...}`,
// `<<: [*a, *b]`) in file in place: the merged entries are written into the
// mapping itself, at the place of the `<<`, and the `<<` entry is dropped.
// goccy merges into a map itself, but decoding into a struct it reports a
// key that overrides a merged one (`http: {<<: *root, status: 404}`) as a
// duplicate, and it cannot merge a list of mappings into a struct at all, so
// Parse and DecodeYAML decode the merged document instead.
//
// A mapping's own key overrides a merged one. YAML has that win wherever the
// key is written, and the first of several merged mappings win, while goccy
// (so the schema's view of a document, and a map field) lets whichever is
// written later win. A document on which the two readings differ is rejected
// rather than read one way: an own key written before the `<<` that merges
// the same key, and a key that two merged mappings both bring (and the
// mapping does not override).
//
// It must run after checkAliases, which bounds the document's expansion and
// guarantees every alias refers to an earlier anchor that does not contain
// it. Merged entries are shared, not copied, and a merged mapping holds each
// key once, so the result is no larger than the expansion checkAliases
// already counted.
func premerge(file *ast.File) error {
	return rewrite(file, true)
}

// rewrite walks every document of file: it resolves merge keys (when merge is
// set, see premerge) and normalises core tags (see retag).
func rewrite(file *ast.File, merge bool) error {
	m := merger{checker: checker{anchors: map[string]ast.Node{}}, merge: merge}
	for _, d := range file.Docs {
		if d == nil || d.Body == nil {
			continue
		}
		clear(m.anchors)
		body, err := m.walk(d.Body)
		if err != nil {
			return err
		}
		d.Body = body
	}
	return nil
}

type merger struct {
	checker
	merge bool
}

// walk rewrites n's subtree, children first, so a mapping that is merged
// somewhere has its own merges resolved by then (an alias refers to an
// earlier anchor, which is walked first). It returns the node to put in n's
// place.
func (m merger) walk(n ast.Node) (ast.Node, error) {
	switch v := n.(type) {
	case *ast.AnchorNode:
		val, err := m.walk(v.Value)
		if err != nil {
			return nil, err
		}
		v.Value = val
		m.anchors[v.Name.GetToken().Value] = val
	case *ast.TagNode:
		val, err := m.walk(v.Value)
		if err != nil {
			return nil, err
		}
		v.Value = val
		return retag(v), nil
	case *ast.SequenceNode:
		for i, e := range v.Values {
			val, err := m.walk(e)
			if err != nil {
				return nil, err
			}
			v.Values[i] = val
		}
	case *ast.MappingValueNode:
		val, err := m.walk(v.Value)
		if err != nil {
			return nil, err
		}
		v.Value = val
	case *ast.MappingNode:
		for _, e := range v.Values {
			val, err := m.walk(e.Value)
			if err != nil {
				return nil, err
			}
			e.Value = val
		}
		if m.merge {
			return v, m.mergeInto(v)
		}
	}
	return n, nil
}

// retag returns the node a core-tagged node decodes as. goccy cannot decode
// `!!int 80` into an integer field, and reads `!!str 0x10` as "16" rather
// than the string "0x10" YAML says it is, so a tag that restates its value's
// type is dropped, and `!!str` on any other scalar becomes a string node with
// the scalar's text. Any other tagged node is returned as is: checkTag has
// rejected the tags a contract may not use.
func retag(v *ast.TagNode) ast.Node {
	val := v.Value
	set := func(n ast.Node) ast.Node { return n }
	if a, ok := val.(*ast.AnchorNode); ok { // !!str &a 1
		val = a.Value
		set = func(n ast.Node) ast.Node { a.Value = n; return a }
	}
	switch name := normTag(v.Start.Value); name {
	case "!!str":
		switch x := val.(type) {
		case *ast.StringNode, *ast.LiteralNode:
			return set(val)
		case *ast.IntegerNode, *ast.FloatNode, *ast.BoolNode, *ast.InfinityNode, *ast.NanNode:
			tk := x.GetToken().Clone()
			tk.Type = token.StringType
			return set(ast.String(tk))
		}
	default:
		ok := false
		switch val.(type) {
		case *ast.IntegerNode:
			ok = name == "!!int"
		case *ast.FloatNode:
			ok = name == "!!float"
		case *ast.BoolNode:
			ok = name == "!!bool"
		case *ast.NullNode:
			ok = name == "!!null"
		case *ast.SequenceNode:
			ok = name == "!!seq"
		case *ast.MappingNode:
			ok = name == "!!map"
		}
		if ok {
			return set(val)
		}
	}
	return v
}

// mergeInto resolves the merge key of mapping v, whose children are merged.
func (m merger) mergeInto(v *ast.MappingNode) error {
	at := -1
	for i, e := range v.Values {
		if e.Key.IsMergeKey() {
			if at >= 0 {
				return nil // two << keys: the decoder reports the duplicate
			}
			at = i
		}
	}
	if at < 0 {
		return nil
	}
	own := map[string]int{} // key -> index of its last own entry
	for i, e := range v.Values {
		if i != at {
			own[m.keyName(e.Key)] = i
		}
	}
	src := m.unwrap(v.Values[at].Value)
	sources := []ast.Node{src}
	if seq, ok := src.(*ast.SequenceNode); ok {
		sources = sources[:0]
		for _, s := range seq.Values {
			sources = append(sources, m.unwrap(s))
		}
	}
	var merged []*ast.MappingValueNode
	from := map[string]*ast.MappingValueNode{}
	for _, s := range sources {
		entries, ok := mappingEntries(s)
		if !ok {
			return nil // not a mapping: left for the decoder and the type check to report
		}
		inSource := map[string]bool{}
		for _, e := range entries {
			if e.Key.IsMergeKey() {
				return nil // a merge the walk could not resolve (a malformed source): left as is
			}
			k := m.keyName(e.Key)
			if inSource[k] {
				return se(lineOf(e.Key), "duplicate key %q in a mapping merged by <<", k)
			}
			inSource[k] = true
			if i, ok := own[k]; ok {
				if i < at {
					return se(lineOf(v.Values[i].Key), "key %q overrides a key merged by a later <<; write it after the << (YAML readers differ on which one wins)", k)
				}
				continue
			}
			if prev, ok := from[k]; ok {
				if prev != e {
					return se(lineOf(v.Values[at].Key), "key %q is merged from more than one mapping; override it in the mapping itself, or merge it from one only (YAML readers differ on which one wins)", k)
				}
				continue
			}
			from[k] = e
			merged = append(merged, e)
		}
	}
	values := make([]*ast.MappingValueNode, 0, len(v.Values)-1+len(merged))
	values = append(values, v.Values[:at]...)
	values = append(values, merged...)
	values = append(values, v.Values[at+1:]...)
	v.Values = values
	return nil
}

// decodeMerged decodes data into v as unmarshal does, but from the document
// with its merge keys resolved by premerge. perr is the parser's error for
// data, if any; the decoder then reports the syntax error itself.
func decodeMerged(data []byte, v any, perr error, opts ...yaml.DecodeOption) (err error) {
	if perr != nil {
		return unmarshal(data, v, perr, opts...)
	}
	file, perr := parser.ParseBytes(data, 0)
	if perr != nil {
		return unmarshal(data, v, perr, opts...)
	}
	if err := premerge(file); err != nil {
		return err
	}
	var body ast.Node
	for _, d := range file.Docs {
		if d != nil && d.Body != nil {
			body = d.Body
			break
		}
	}
	if body == nil {
		return nil // an empty document decodes to nothing, as with Unmarshal
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid YAML: the document could not be decoded (%v)", r)
		}
	}()
	if err := yaml.NodeToValue(body, v, opts...); err != nil {
		return fmt.Errorf("invalid YAML: %s", strings.TrimSpace(yaml.FormatError(err, false, false)))
	}
	return nil
}
