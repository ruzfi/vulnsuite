package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// run and build refuse a template that validate would reject, before any
// image or container work. A probe regex that does not compile used to be
// noticed only by validate: run pulled, started and then "verified" with it.
func TestRunAndBuildRejectInvalidTemplateUpFront(t *testing.T) {
	root := t.TempDir()
	if err := os.CopyFS(root, os.DirFS(fixtures(t))); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "web-apps", "grafana-cve-2021-43798", "contract.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(b), `body_matches: "root:.*:0:0:"`, `body_matches: "root:(.*:0:0:"`, 1)
	if broken == string(b) {
		t.Fatal("fixture changed: no body_matches to break")
	}
	os.WriteFile(p, []byte(broken), 0o644)

	for _, args := range [][]string{
		{"run", "-t", "grafana", "-detach", "-ready-timeout", "1s"},
		{"build", "-t", "grafana"},
	} {
		fe := enginetest.New()
		code, out, errOut := run(t, fe, append([]string{"-T", root}, args...)...)
		if code != ExitFail || !strings.Contains(errOut, "bad-regex") {
			t.Errorf("%v: exit %d\n%s\n%s", args, code, out, errOut)
		}
		if len(fe.Pulls)+len(fe.Builds)+len(fe.Containers) != 0 {
			t.Errorf("%v: engine used: pulls=%v builds=%d containers=%d", args, fe.Pulls, len(fe.Builds), len(fe.Containers))
		}
	}

	// -json -summary carries it as a load failure, so a pipeline sees why.
	code, out, _ := run(t, enginetest.New(), "-json", "-T", root, "run", "-t", "grafana", "-detach", "-summary")
	var sum struct {
		Failed []struct{ ID, Reason, Detail string } `json:"failed"`
	}
	if code != ExitFail || json.Unmarshal([]byte(out), &sum) != nil || len(sum.Failed) != 1 ||
		sum.Failed[0].ID != "grafana-8.3.0-cve-2021-43798" || !strings.Contains(sum.Failed[0].Detail, "bad-regex") {
		t.Fatalf("run -json -summary: exit %d\n%s", code, out)
	}

	// Other templates in the same tree are unaffected.
	if code, out, errOut := run(t, enginetest.New(), "-T", root, "build", "-t", "apache"); code != ExitOK {
		t.Fatalf("build apache: %d\n%s\n%s", code, out, errOut)
	}
}
