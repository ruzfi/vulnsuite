package contract

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml/parser"
)

// withStates returns testdata/good/anchors-and-literals.yaml with its states
// replaced by states (indented under `states:`), plus extra top-level YAML
// before them.
func withStates(t *testing.T, extra, states string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/good/anchors-and-literals.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Windows checkouts (text=auto) carry CRLF line endings.
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	i := strings.Index(s, "states:\n")
	if i < 0 {
		t.Fatal("no states in the base contract")
	}
	return s[:i] + extra + "states:\n" + states
}

const patchedState = "  patched:\n    image: httpd:2.4.51\n    verify:\n      - http: { path: /, status: 404 }\n"

// TestAliasBombsFailFast checks that documents which expand exponentially
// through aliases or merge keys are rejected before the decoder expands them.
// Without the expansion cap the merge case hangs inside goccy's decoder (each
// level multiplies the work by four).
func TestAliasBombsFailFast(t *testing.T) {
	var laughs, merges, fanout strings.Builder
	// The classic: ten levels of ten aliases each, under a typed field.
	laughs.WriteString("  vulnerable:\n    environment: { A: &a0 lol }\n    verify:\n      - http: { path: /, status: 200 }\n")
	for i := 1; i <= 9; i++ {
		fmt.Fprintf(&laughs, "      - http: { path: /, status_in: &a%d [", i)
		for j := 0; j < 10; j++ {
			if j > 0 {
				laughs.WriteString(", ")
			}
			fmt.Fprintf(&laughs, "*a%d", i-1)
		}
		laughs.WriteString("] }\n")
	}
	// Nested merge keys: each level merges the previous one four times.
	merges.WriteString("  vulnerable:\n    verify:\n      - tcp: &m0 { port: 80 }\n")
	for i := 1; i <= 25; i++ {
		fmt.Fprintf(&merges, "      - tcp: &m%d { <<: [*m%[2]d, *m%[2]d, *m%[2]d, *m%[2]d] }\n", i, i-1)
	}
	// Quadratic fan-out: k probes, each with k steps.
	const k = 2000
	fanout.WriteString("  vulnerable:\n    verify:\n      - &p { net: { port: 80, steps: [&s { expect: x }")
	for i := 0; i < k; i++ {
		fanout.WriteString(", *s")
	}
	fanout.WriteString("] } }\n")
	for i := 0; i < k; i++ {
		fanout.WriteString("      - *p\n")
	}
	for name, states := range map[string]string{
		"laughs": laughs.String(), "merges": merges.String(), "fanout": fanout.String(),
	} {
		t.Run(name, func(t *testing.T) {
			doc := withStates(t, "", states+patchedState)
			start := time.Now()
			_, err := Parse([]byte(doc))
			if err == nil || !strings.Contains(err.Error(), "expands to more than") {
				t.Fatalf("want an expansion error, got %v", err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("rejecting took %v", d)
			}
		})
	}
}

func TestAliasStructure(t *testing.T) {
	for name, tc := range map[string]struct{ states, want string }{
		"self reference": {
			"  vulnerable:\n    verify:\n      - http: &h { path: /, status: 200, headers: *h }\n",
			"alias *h refers to a node that contains it",
		},
		"undefined anchor": {
			"  vulnerable:\n    verify:\n      - http: { path: /, status: *nope }\n",
			"alias *nope does not refer to an earlier anchor",
		},
		"alias before anchor": {
			"  vulnerable:\n    verify:\n      - http: { path: /, status: *ok }\n      - http: { path: /x, status: &ok 200 }\n",
			"alias *ok does not refer to an earlier anchor",
		},
		"duplicate anchor": {
			"  vulnerable:\n    verify:\n      - http: { path: /, status: &ok 200 }\n      - http: { path: /x, status: &ok \"200\" }\n      - http: { path: /y, status: *ok }\n",
			"anchor &ok is defined more than once",
		},
		"wrong-typed alias at a probe port": {
			"  vulnerable:\n    environment: { PORT: &p \"8080\" }\n    verify:\n      - http: { path: /, port: *p, status: 200 }\n",
			"states/vulnerable/verify/0/http/port: must be an integer",
		},
		"zero port through an alias": {
			"  vulnerable:\n    verify:\n      - http: { path: /, status_in: [&z 0, 200] }\n      - tcp: { port: *z }\n",
			"must be 1..65535",
		},
		"wrong-typed merge into a map": {
			"  vulnerable:\n    environment: { <<: { FLAG: true } }\n    verify:\n      - http: { path: /, status: 200 }\n",
			"states/vulnerable/environment/FLAG: must be a string",
		},
		"merge of a scalar": {
			"  vulnerable:\n    verify:\n      - http: { <<: *s, path: / }\n",
			"does not refer to an earlier anchor",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(withStates(t, "", tc.states+patchedState)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// TestCheckDocumentMergedUnknownField checks the type checker on its own: a key
// merged into a struct must be a field of it, as an inline key must. (Parse
// reports this through the strict decoder first.)
func TestCheckDocumentMergedUnknownField(t *testing.T) {
	doc := withStates(t, "", "  vulnerable:\n    verify:\n      - http: { <<: { owner: me }, path: /, status: 200 }\n"+patchedState)
	file, err := parser.ParseBytes([]byte(doc), 0)
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := checkAliases(file)
	if err != nil {
		t.Fatal(err)
	}
	err = checkDocument(file, anchors)
	if err == nil || !strings.Contains(err.Error(), `states/vulnerable/verify/0/http/owner: unknown field "owner"`) {
		t.Fatalf("want an unknown-field error, got %v", err)
	}
}
