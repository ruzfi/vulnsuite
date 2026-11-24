package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// suiteFixtures copies the fixtures and adds two suites: "pair" (two
// targets) and "one" (a single target).
func suiteFixtures(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.CopyFS(root, os.DirFS(fixtures(t))); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "suites", "pair.txt"), "# two targets\ngrafana\nredis-unauthenticated-access\n")
	writeFile(t, filepath.Join(root, "suites", "one.txt"), "exposed-dotenv-file\n")
	return root
}

// #147 item 7: suite:<name> works on list, validate, info and stop, with the
// resolver run/build/stamp use.
func TestSuiteSelectorOnListValidateInfoStop(t *testing.T) {
	isolateHome(t)
	t.Setenv("NUCLEI_TEMPLATES", "")
	root := suiteFixtures(t)

	code, out, errOut := run(t, nil, "-json", "-T", root, "list", "suite:pair")
	var rows []listRow
	if code != ExitOK || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 2 {
		t.Fatalf("list suite:pair: %d\n%s\n%s", code, out, errOut)
	}
	ids := rows[0].ID + " " + rows[1].ID
	if !strings.Contains(ids, "grafana-8.3.0-cve-2021-43798") || !strings.Contains(ids, "redis-unauthenticated-access") {
		t.Fatalf("list suite:pair rows: %s", ids)
	}
	if code, _, errOut := run(t, nil, "-T", root, "list", "suite:nope"); code == ExitOK || !strings.Contains(errOut, `no suite "nope"`) {
		t.Fatalf("list suite:nope: %d\n%s", code, errOut)
	}

	code, out, errOut = run(t, nil, "-json", "-T", root, "validate", "-allow-unpinned", "-t", "suite:pair")
	var v struct{ Templates int }
	if json.Unmarshal([]byte(out), &v) != nil || v.Templates != 2 {
		t.Fatalf("validate -t suite:pair: %d\n%s\n%s", code, out, errOut)
	}

	code, out, errOut = run(t, nil, "-T", root, "info", "suite:pair")
	if code != ExitOK || !strings.Contains(out, "suite:pair  (suite, 2 targets)") || !strings.Contains(out, "redis-unauthenticated-access") {
		t.Fatalf("info suite:pair: %d\n%s\n%s", code, out, errOut)
	}
	code, out, errOut = run(t, nil, "-T", root, "info", "suite:one")
	if code != ExitOK || !strings.HasPrefix(out, "exposed-dotenv-file\n") {
		t.Fatalf("info suite:one: %d\n%s\n%s", code, out, errOut)
	}

	fe := enginetest.New()
	if code, out, errOut := run(t, fe, "-T", root, "run", "-t", "suite:pair", "-detach", "-no-verify", "-ready-timeout", "1s"); code != ExitOK {
		t.Fatalf("run suite:pair: %d\n%s\n%s", code, out, errOut)
	}
	if len(fe.Containers) == 0 {
		t.Fatal("nothing started")
	}
	code, out, errOut = run(t, fe, "-T", root, "stop", "-t", "suite:pair")
	if code != ExitOK || !strings.Contains(out, "stopped") {
		t.Fatalf("stop -t suite:pair: %d\n%s\n%s", code, out, errOut)
	}
	if len(fe.Containers) != 0 {
		t.Fatalf("still running after stop -t suite:pair: %v", fe.Containers)
	}
}

// #147 item 4: -group lists one group; positional selectors next to it used
// to be dropped silently.
func TestListGroupWithSelectorsIsUsageError(t *testing.T) {
	isolateHome(t)
	root := groupFixtures(t)
	for _, args := range [][]string{
		{"-T", root, "list", "php2shell-waf", "-group", "php2shell"},
		{"-T", root, "list", "-group", "php2shell", "php2shell-waf"},
	} {
		code, _, errOut := run(t, nil, args...)
		if code != ExitUsage || !strings.Contains(errOut, "-group") {
			t.Fatalf("%v: code=%d\n%s", args, code, errOut)
		}
	}
}

// #147 item 3: stamp with an empty selection fails like build's "nothing to
// build", instead of exiting 0 having stamped nothing.
func TestStampEmptySelectionFails(t *testing.T) {
	root, _ := stampRoot(t)
	code, out, errOut := run(t, stampEngine(t), "-T", root, "stamp", "-expose", "host", "-class", "weak-crypto")
	if code != ExitFail || !strings.Contains(errOut, "nothing to stamp") {
		t.Fatalf("stamp with nothing selected: %d\n%s\n%s", code, out, errOut)
	}
	code, out, _ = run(t, stampEngine(t), "-T", root, "-json", "stamp", "-expose", "host", "-class", "weak-crypto")
	if code != ExitFail || strings.TrimSpace(out) != "[]" {
		t.Fatalf("stamp -json with nothing selected: %d\n%s", code, out)
	}
}
