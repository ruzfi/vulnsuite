package cli

import (
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// Commands that take flags only must refuse a stray positional instead of
// ignoring it: `images -rm grafana` used to remove every vulnsuite image,
// and `update-templates v2` quietly updated main.
func TestFlagOnlyCommandsRejectArguments(t *testing.T) {
	root := fixtures(t)
	for _, args := range [][]string{
		{"images", "-rm", "grafana"},
		{"images", "grafana", "-rm"},
		{"update-templates", "v2"},
		{"ps", "grafana"},
		{"targets", "grafana"},
		{"version", "x"},
	} {
		fe := enginetest.New()
		fe.Images["vulnsuite/grafana:vulnerable-abc"] = true
		fe.Images["vulnsuite/other:vulnerable-def"] = true
		code, _, errOut := run(t, fe, append([]string{"-T", root}, args...)...)
		if code != ExitUsage || !strings.Contains(errOut, "unexpected argument") {
			t.Errorf("%v: exit %d, stderr %q; want a usage error", args, code, errOut)
		}
		if len(fe.Images) != 2 {
			t.Errorf("%v: images removed: %v", args, fe.Images)
		}
	}
	// Flags alone still work.
	if code, _, errOut := run(t, enginetest.New(), "-T", root, "images"); code != ExitOK {
		t.Fatalf("images: %d %s", code, errOut)
	}
}

func TestHelpUnknownCommandIsUsageError(t *testing.T) {
	if code, out, errOut := run(t, nil, "help", "nosuch"); code != ExitUsage || out != "" || !strings.Contains(errOut, `unknown command "nosuch"`) {
		t.Fatalf("help nosuch: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if code, out, _ := run(t, nil, "help", "run"); code != ExitOK || !strings.Contains(out, "vulnsuite run") {
		t.Fatalf("help run: exit %d\n%s", code, out)
	}
}

// A malformed -ready-timeout is a usage error caught with the other flag
// checks, before any engine work.
func TestReadyTimeoutCheckedFirst(t *testing.T) {
	fe := enginetest.New()
	code, _, errOut := run(t, fe, "-T", fixtures(t), "run", "-t", "grafana", "-ready-timeout", "bogus")
	if code != ExitUsage || !strings.Contains(errOut, "-ready-timeout") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if len(fe.Builds) != 0 || len(fe.Pulls) != 0 || len(fe.Containers) != 0 {
		t.Fatalf("engine was used before the flag check: builds=%d pulls=%d containers=%d", len(fe.Builds), len(fe.Pulls), len(fe.Containers))
	}
}
