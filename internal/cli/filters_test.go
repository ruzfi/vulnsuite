package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// #47 item 2: a filter value that cannot match anything is a usage error (exit
// 2) on list, run and build alike, not a filter that silently selects nothing.
func TestFilterValuesAreValidated(t *testing.T) {
	isolateHome(t)
	root := fixtures(t)
	bad := []struct {
		flag, value, want string
	}{
		{"-fidelity", "reel", `unknown -fidelity "reel"`},
		{"-year", "21", `-year wants a four-digit year`},
		{"-year", "20211", `-year wants a four-digit year`},
		{"-since", "2023/01/01", `-since wants an ISO date`},
		{"-since", "2023-1-1", `-since wants an ISO date`},
		{"-since", "2023-02-30", `-since wants an ISO date`},
		{"-arch", "amd46", `unknown -arch "amd46"`},
		{"-category", "web-app", `unknown -category "web-app"; the templates directory has databases, exposures, iot, web-apps, web-servers`},
		{"-product", "web-app", `unknown -category "web-app"`},
	}
	for _, cmd := range []string{"list", "run", "build"} {
		for _, b := range bad {
			t.Run(cmd+b.flag+"="+b.value, func(t *testing.T) {
				code, out, errOut := run(t, enginetest.New(), "-T", root, cmd, b.flag, b.value)
				if code != ExitUsage || !strings.Contains(errOut, b.want) {
					t.Fatalf("%s %s %s: exit %d, want %d with %q\nstdout: %s\nstderr: %s", cmd, b.flag, b.value, code, ExitUsage, b.want, out, errOut)
				}
				if out != "" {
					t.Fatalf("a usage error must not write stdout: %q", out)
				}
			})
		}
	}
	// Well-formed values still work (and may simply match nothing).
	for _, args := range [][]string{
		{"-fidelity", "real"}, {"-fidelity", "simulated"},
		{"-year", "2021"}, {"-since", "2023-01-01"},
		{"-arch", "arm64"}, {"-arch", "loong64"}, {"-category", "web-apps"},
	} {
		if code, out, errOut := run(t, nil, append([]string{"-json", "-T", root, "list"}, args...)...); code != ExitOK {
			t.Fatalf("list %v: %d\n%s\n%s", args, code, out, errOut)
		}
	}
}

// #47 item 2: a mistake inside a -f or suite file names the file and line.
func TestSelectorFileErrorsNameFileLine(t *testing.T) {
	isolateHome(t)
	root := fixtures(t)
	dir := t.TempDir()

	// An unmatched selector on line 3 (after a comment and a good selector).
	f := filepath.Join(dir, "targets.txt")
	writeFile(t, f, "# set\ngrafana\nno-such-target-xyz\n")
	for _, cmd := range []string{"run", "build"} {
		code, _, errOut := run(t, enginetest.New(), "-T", root, cmd, "-f", f)
		if code == ExitOK || !strings.Contains(errOut, f+":3: ") || !strings.Contains(errOut, "no-such-target-xyz") {
			t.Fatalf("%s -f unmatched selector: exit %d\n%s", cmd, code, errOut)
		}
	}

	// A bad filter value on line 2 is a usage error, like the same flag.
	writeFile(t, f, "grafana\n-fidelity reel\n")
	code, _, errOut := run(t, enginetest.New(), "-T", root, "build", "-f", f)
	if code != ExitUsage || !strings.Contains(errOut, f+`:2: unknown -fidelity "reel"`) {
		t.Fatalf("build -f bad filter line: exit %d\n%s", code, errOut)
	}
	writeFile(t, f, "grafana\n-category web-app\n")
	code, _, errOut = run(t, enginetest.New(), "-T", root, "build", "-f", f)
	if code != ExitUsage || !strings.Contains(errOut, f+`:2: unknown -category "web-app"`) {
		t.Fatalf("build -f bad category line: exit %d\n%s", code, errOut)
	}
	writeFile(t, f, "\n\n-nope\n")
	code, _, errOut = run(t, enginetest.New(), "-T", root, "build", "-f", f)
	if code != ExitUsage || !strings.Contains(errOut, f+":3: bad filter line") {
		t.Fatalf("build -f unknown filter flag: exit %d\n%s", code, errOut)
	}

	// A suite's own lines are named too, and a missing nested suite names the
	// line that references it.
	suites := copyTemplates(t, root)
	writeFile(t, filepath.Join(suites, "suites", "web.txt"), "grafana\n\nbogus-selector-xyz\n")
	code, _, errOut = run(t, enginetest.New(), "-T", suites, "build", "-t", "suite:web")
	if code == ExitOK || !strings.Contains(errOut, filepath.Join(suites, "suites", "web.txt")+":3: ") {
		t.Fatalf("suite unmatched selector: exit %d\n%s", code, errOut)
	}
	writeFile(t, f, "grafana\nsuite:missing\n")
	code, _, errOut = run(t, enginetest.New(), "-T", suites, "build", "-f", f)
	if code == ExitOK || !strings.Contains(errOut, f+`:2: no suite "missing"`) {
		t.Fatalf("missing suite: exit %d\n%s", code, errOut)
	}
}

// copyTemplates copies the fixture tree so a test can add suites to it.
func copyTemplates(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(fmt.Errorf("copy templates: %w", err))
	}
	return dst
}

// #95: an explicit scanner directory that is not a directory is a usage
// error, not a silent fallback to $NUCLEI_TEMPLATES or ~/nuclei-templates.
func TestScannerDirFlagsMustBeDirectories(t *testing.T) {
	isolateHome(t)
	t.Setenv("NUCLEI_TEMPLATES", "")
	root := fixtures(t)
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	file := filepath.Join(t.TempDir(), "file.yaml")
	writeFile(t, file, "id: x\n")
	cases := [][]string{
		{"info", "-nuclei-templates", missing, "grafana"},
		{"info", "-nuclei-templates", file, "grafana"},
		{"validate", "-allow-unpinned", "-nuclei-templates", missing},
		{"validate", "-allow-unpinned", "-nmap-scripts", file},
		{"run", "-t", "grafana", "-detach", "-no-verify", "-nuclei-templates", missing},
	}
	for _, args := range cases {
		code, out, errOut := run(t, enginetest.New(), append([]string{"-T", root}, args...)...)
		flagName := "-nuclei-templates "
		if strings.Contains(strings.Join(args, " "), "-nmap-scripts") {
			flagName = "-nmap-scripts "
		}
		if code != ExitUsage || !strings.Contains(errOut, flagName) {
			t.Fatalf("%v: exit %d, want %d\nstdout: %s\nstderr: %s", args, code, ExitUsage, out, errOut)
		}
	}
	// A real directory is accepted.
	if code, out, errOut := run(t, nil, "-T", root, "info", "-nuclei-templates", t.TempDir(), "grafana"); code != ExitOK {
		t.Fatalf("info with an empty checkout: %d\n%s\n%s", code, out, errOut)
	}
}
