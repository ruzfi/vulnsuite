package cli

import (
	"encoding/json"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

const grafanaID = "grafana-8.3.0-cve-2021-43798"

// #47 item 13: run takes the state positional anywhere among its positionals,
// and flags may follow positionals.
func TestRunStatePositionalAnywhere(t *testing.T) {
	isolateHome(t)
	root := fixtures(t)
	for _, args := range [][]string{
		{"run", "grafana", "patched", "-detach", "-no-verify", "-ready-timeout", "1s"},
		{"run", "-detach", "grafana", "patched", "-no-verify", "-ready-timeout", "1s"},
		{"run", "-t", "grafana", "patched", "-detach", "-no-verify", "-ready-timeout", "1s"},
		{"run", "patched", "-t", "grafana", "-detach", "-no-verify", "-ready-timeout", "1s"},
	} {
		fe := enginetest.New()
		code, out, errOut := run(t, fe, append([]string{"-T", root}, args...)...)
		if code != ExitOK {
			t.Fatalf("%v: %d\n%s\n%s", args, code, out, errOut)
		}
		if fe.Containers["vulnsuite-"+grafanaID+"-patched"] == nil || len(fe.Containers) != 1 {
			t.Fatalf("%v: want only the patched container, got %v", args, keys(fe.Containers))
		}
	}
	// Default is still vulnerable.
	fe := enginetest.New()
	if code, out, errOut := run(t, fe, "-T", root, "run", "grafana", "-detach", "-no-verify", "-ready-timeout", "1s"); code != ExitOK || fe.Containers["vulnsuite-"+grafanaID+"-vulnerable"] == nil {
		t.Fatalf("default state: %d\n%s\n%s", code, out, errOut)
	}
	// Two different states is a usage error; repeating one is fine.
	code, out, errOut := run(t, enginetest.New(), "-T", root, "run", "vulnerable", "grafana", "patched", "-detach")
	if code != ExitUsage || !strings.Contains(errOut, "two states") || out != "" {
		t.Fatalf("two states: %d\n%s\n%s", code, out, errOut)
	}
}

// #47 item 13: build takes the state positional as shorthand for -state.
func TestBuildStatePositional(t *testing.T) {
	isolateHome(t)
	root := fixtures(t)
	for _, args := range [][]string{
		{"build", "patched", "-t", "grafana"},
		{"build", "-t", "grafana", "patched"},
		{"build", "grafana", "patched"},
		{"build", "patched", "grafana", "-state", "patched"},
	} {
		code, out, errOut := run(t, enginetest.New(), append([]string{"-json", "-T", root}, args...)...)
		var res []buildResult
		if code != ExitOK || json.Unmarshal([]byte(out), &res) != nil {
			t.Fatalf("%v: %d\n%s\n%s", args, code, out, errOut)
		}
		if len(res) != 1 || res[0].ID != grafanaID || res[0].State != "patched" {
			t.Fatalf("%v: want only grafana [patched], got %s", args, out)
		}
	}
	// A positional state that contradicts an explicit -state is a usage error.
	for _, st := range []string{"vulnerable", "all"} {
		code, out, errOut := run(t, enginetest.New(), "-T", root, "build", "patched", "-t", "grafana", "-state", st)
		if code != ExitUsage || !strings.Contains(errOut, "contradicts -state") {
			t.Fatalf("-state %s: %d\n%s\n%s", st, code, out, errOut)
		}
	}
}

// A selector spelled like a state stays reachable through -t.
func TestStateNamedSelectorViaFlag(t *testing.T) {
	isolateHome(t)
	root := fixtures(t)
	code, _, errOut := run(t, enginetest.New(), "-T", root, "build", "-t", "patched")
	if code == ExitOK || !strings.Contains(errOut, `patched`) || strings.Contains(errOut, "pass -t") {
		t.Fatalf("-t patched should be resolved as a selector: %d\n%s", code, errOut)
	}
}

func TestParseInterleaved(t *testing.T) {
	cases := []struct {
		args []string
		pos  string
		sel  string
		on   bool
	}{
		{[]string{"a", "-t", "x", "b", "-b", "c"}, "a b c", "x", true},
		{[]string{"-b", "a", "--", "-t", "y"}, "a -t y", "", true},
		{[]string{"a", "-", "b"}, "a - b", "", false},
		{[]string{"-t", "x", "-"}, "-", "x", false},
	}
	for _, c := range cases {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var sel multiFlag
		fs.Var(&sel, "t", "")
		on := fs.Bool("b", false, "")
		pos, err := parseInterleaved(fs, c.args)
		if err != nil || strings.Join(pos, " ") != c.pos || strings.Join(sel, " ") != c.sel || *on != c.on {
			t.Fatalf("%v: pos=%q sel=%q b=%v err=%v", c.args, pos, sel, *on, err)
		}
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
