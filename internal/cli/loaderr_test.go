package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// brokenFixtures copies the fixtures and breaks two contracts: grafana keeps a
// readable metadata.id but gains an unknown field (strict decoding rejects
// it); a new folder holds a contract that is not YAML at all.
func brokenFixtures(t *testing.T) (root, grafana string) {
	t.Helper()
	root = t.TempDir()
	if err := os.CopyFS(root, os.DirFS(fixtures(t))); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(root, "*", "*grafana*", "contract.yaml"))
	if len(matches) != 1 {
		t.Fatalf("grafana fixture: %v", matches)
	}
	grafana = matches[0]
	f, err := os.OpenFile(grafana, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("\nnot_a_contract_field: true\n")
	f.Close()
	garbled := filepath.Join(root, "web-apps", "garbled-target")
	os.MkdirAll(garbled, 0o755)
	os.WriteFile(filepath.Join(garbled, "contract.yaml"), []byte("apiVersion: vulnsuite/v1\nmetadata: [unclosed\n"), 0o644)
	return root, grafana
}

// list used to exit 0 with unloadable templates, and their -json rows had
// "id": "" and null where arrays are documented.
func TestListReportsUnloadableTemplates(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, _ := brokenFixtures(t)
	code, out, errOut := run(t, nil, "-T", root, "list")
	if code != ExitFail || !strings.Contains(out, "unloadable") || !strings.Contains(errOut, "2 template(s) failed to load") {
		t.Fatalf("list: exit %d\n%s\n%s", code, out, errOut)
	}
	code, out, _ = run(t, nil, "-T", root, "-json", "list")
	if code != ExitFail {
		t.Fatalf("list -json: exit %d", code)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("list -json output: %v\n%s", err, out)
	}
	ids := map[string]bool{}
	for _, r := range rows {
		if r["error"] == nil {
			continue
		}
		id, _ := r["id"].(string)
		ids[id] = true
		for _, k := range []string{"states", "vuln_refs"} {
			if _, ok := r[k].([]any); !ok {
				t.Errorf("row %q: %s = %v, want an array", id, k, r[k])
			}
		}
	}
	if !ids["grafana-8.3.0-cve-2021-43798"] || !ids["garbled-target"] || len(ids) != 2 {
		t.Fatalf("unloadable row ids = %v; want the declared id and the folder name", ids)
	}
}

// stop -t used to drop load errors, print "nothing to stop", exit 0 and leave
// the target running once its contract no longer loaded.
func TestStopTargetWhoseContractBroke(t *testing.T) {
	root := t.TempDir()
	if err := os.CopyFS(root, os.DirFS(fixtures(t))); err != nil {
		t.Fatal(err)
	}
	fe := enginetest.New()
	if code, out, errOut := run(t, fe, "-T", root, "run", "-t", "grafana", "-detach", "-no-verify", "-ready-timeout", "1s"); code != ExitOK {
		t.Fatalf("run: %d\n%s\n%s", code, out, errOut)
	}
	name := "vulnsuite-grafana-8.3.0-cve-2021-43798-vulnerable"
	if fe.Containers[name] == nil {
		t.Fatalf("not started: %v", fe.Containers)
	}
	// The contract breaks after an update, id still readable.
	matches, _ := filepath.Glob(filepath.Join(root, "*", "*grafana*", "contract.yaml"))
	f, _ := os.OpenFile(matches[0], os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("\nnot_a_contract_field: true\n")
	f.Close()
	code, out, errOut := run(t, fe, "-T", root, "stop", "-t", "grafana")
	if code != ExitOK || !strings.Contains(out, "stopped 1 container") || !strings.Contains(errOut, "by its declared id") {
		t.Fatalf("stop: exit %d\n%s\n%s", code, out, errOut)
	}
	if fe.Containers[name] != nil {
		t.Fatal("the target is still running")
	}
	// Unreadable even as YAML: an error, not "nothing to stop".
	os.WriteFile(matches[0], []byte("metadata: [unclosed\n"), 0o644)
	code, out, errOut = run(t, fe, "-T", root, "stop", "-t", matches[0])
	if code != ExitFail || strings.Contains(out, "nothing to stop") {
		t.Fatalf("stop of an unreadable contract: exit %d\n%s\n%s", code, out, errOut)
	}
}
