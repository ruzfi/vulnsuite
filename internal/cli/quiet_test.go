package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// -q silences progress, never a command's output: run's "Scan these" URL
// list used to vanish entirely under -q.
func TestQuietRunKeepsTargetURLs(t *testing.T) {
	fe := enginetest.New()
	code, out, errOut := run(t, fe, "-q", "-T", fixtures(t), "run", "-t", "grafana", "-detach", "-no-verify", "-ready-timeout", "1s")
	if code != ExitOK {
		t.Fatalf("run: %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "grafana-8.3.0-cve-2021-43798 [vulnerable]") || !strings.Contains(out, ":3000") {
		t.Fatalf("-q run printed no target URLs:\n%q", out)
	}
	if strings.Contains(out, "Scan these") || strings.Contains(out, "docker run --rm") {
		t.Fatalf("-q run kept the header/hints:\n%s", out)
	}
}

// A "#" comment after a tab is a comment too; it used to become part of the
// selector ("grafana\t# note") and match nothing.
func TestSelectorFileCommentAfterTab(t *testing.T) {
	f := filepath.Join(t.TempDir(), "suite.txt")
	os.WriteFile(f, []byte("grafana\t# the path traversal one\n-class exposure\t#and a filter\n"), 0o644)
	lines, err := parseSelectorFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0].text != "grafana" || strings.Join(lines[1].args, " ") != "-class exposure" {
		t.Fatalf("lines = %+v", lines)
	}
}
