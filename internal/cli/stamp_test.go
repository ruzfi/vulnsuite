package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// stampContract verifies each state with an exec probe, so the fake engine
// decides the outcome through ExecFn.
const stampContract = `apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: stamp-demo
  summary: demo   # kept
  vuln_refs: [VS-STAMP-1]
  verification: unverified
base:
  kind: image
  image: busybox:1
  digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
service:
  ports: [ { container: 80, protocol: tcp } ]
requires:
  cpu_flags: [avx512vbmi]
states:
  vulnerable:
    verify:
      - exec: { run: "check", stdout_matches: "^vulnerable$" }
  patched:
    verify:
      - exec: { run: "check", stdout_matches: "^patched$" }
`

const plainContract = `apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: plain-demo
  summary: demo
base:
  kind: image
  image: busybox:1
service:
  ports: [ { container: 80, protocol: tcp } ]
states:
  vulnerable:
    verify:
      - exec: { run: "check", stdout_matches: "^vulnerable$" }
`

func stampRoot(t *testing.T) (root, path string) {
	t.Helper()
	root = t.TempDir()
	for id, doc := range map[string]string{"stamp-demo": stampContract, "plain-demo": plainContract} {
		dir := filepath.Join(root, "misc", id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, filepath.Join(root, "misc", "stamp-demo", "contract.yaml")
}

// stampEngine answers the exec probe with the state the container runs, or
// with "nothing" for the states in broken; the host has the flag the
// template requires.
func stampEngine(t *testing.T, broken ...string) *enginetest.Fake {
	t.Helper()
	fe := enginetest.New()
	serveOnPublishedPorts(t, fe, "ok")
	fe.HostInfo.CPUFlags, fe.HostInfo.CPUFlagsKnown = []string{"avx512vbmi"}, true
	fe.ExecFn = func(container, command string) (int, string, error) {
		for _, st := range []string{"vulnerable", "patched"} {
			if strings.HasSuffix(container, "-"+st) {
				for _, b := range broken {
					if b == st {
						return 0, "nothing", nil
					}
				}
				return 0, st, nil
			}
		}
		return 1, "", nil
	}
	return fe
}

func TestStampWritesEvidenceWhenEveryStateVerifies(t *testing.T) {
	root, path := stampRoot(t)
	code, out, errOut := run(t, stampEngine(t), "-T", root, "-json", "stamp", "-expose", "host", "-t", "stamp-demo")
	if code != ExitOK {
		t.Fatalf("stamp: %d\n%s\n%s", code, out, errOut)
	}
	var res []stampResult
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res) != 1 || res[0].Outcome != stampStamped {
		t.Fatalf("stamp -json: %v\n%s", err, out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := contract.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	vo := c.Metadata.VerifiedOn
	if c.IsUnverified() || vo == nil || vo.Host != "linux/amd64" || strings.Join(vo.States, ",") != "vulnerable,patched" ||
		strings.Join(vo.CPUFlags, ",") != "avx512vbmi" || vo.Vulnsuite == "" || vo.Date == "" {
		t.Fatalf("stamped metadata: %+v %+v\n%s", c.Metadata, vo, data)
	}
	if !strings.Contains(string(data), "summary: demo   # kept") {
		t.Fatalf("the rest of the file must be left as it was:\n%s", data)
	}
	// The stamped target no longer warns.
	if _, vout, _ := run(t, nil, "-T", root, "validate", "-t", "stamp-demo"); strings.Contains(vout, "unverified-target") {
		t.Fatalf("validate after stamp:\n%s", vout)
	}
}

func TestStampLeavesFileUntouchedOnFailure(t *testing.T) {
	root, path := stampRoot(t)
	before, _ := os.ReadFile(path)
	code, out, errOut := run(t, stampEngine(t, "patched"), "-T", root, "stamp", "-expose", "host", "-t", "stamp-demo")
	if code == ExitOK || !strings.Contains(errOut, "not stamped stamp-demo: patched") {
		t.Fatalf("stamp with a failing state: %d\n%s\n%s", code, out, errOut)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("file changed although a state failed:\n%s", after)
	}
	// -dry-run verifies without writing.
	code, out, errOut = run(t, stampEngine(t), "-T", root, "stamp", "-expose", "host", "-dry-run", "-t", "stamp-demo")
	if code != ExitOK || !strings.Contains(out, "verified stamp-demo (-dry-run") {
		t.Fatalf("stamp -dry-run: %d\n%s\n%s", code, out, errOut)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("-dry-run wrote the file")
	}
}

func TestStampSkipsWhenHostLacksRequires(t *testing.T) {
	root, path := stampRoot(t)
	before, _ := os.ReadFile(path)
	fe := stampEngine(t)
	fe.HostInfo.CPUFlags = []string{"sse2"}
	code, out, errOut := run(t, fe, "-T", root, "stamp", "-expose", "host", "-t", "stamp-demo")
	if code != ExitOK || !strings.Contains(out, "skip stamp-demo") {
		t.Fatalf("stamp on a host without the flag: %d\n%s\n%s", code, out, errOut)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("file changed although the target was skipped")
	}
	if code, _, _ := run(t, fe, "-T", root, "stamp", "patched", "-t", "stamp-demo"); code != ExitUsage {
		t.Fatalf("a state argument must be a usage error, got %d", code)
	}
}

func TestListAndInfoShowVerification(t *testing.T) {
	root, _ := stampRoot(t)
	code, out, errOut := run(t, nil, "-T", root, "list", "-unverified")
	if code != ExitOK || !strings.Contains(out, "stamp-demo") || strings.Contains(out, "plain-demo") || !strings.Contains(out, "VERIFIED") {
		t.Fatalf("list -unverified: %d\n%s\n%s", code, out, errOut)
	}
	code, out, _ = run(t, nil, "-T", root, "list", "-verified")
	if code != ExitOK || strings.Contains(out, "stamp-demo") || !strings.Contains(out, "plain-demo") {
		t.Fatalf("list -verified: %d\n%s", code, out)
	}
	if code, _, _ := run(t, nil, "-T", root, "list", "-verified", "-unverified"); code != ExitUsage {
		t.Fatalf("-verified -unverified must be a usage error, got %d", code)
	}
	code, out, _ = run(t, nil, "-T", root, "-json", "list", "-variants")
	var rows []listRow
	if code != ExitOK || json.Unmarshal([]byte(out), &rows) != nil {
		t.Fatalf("list -json: %d\n%s", code, out)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.ID] = r.Verification
	}
	if got["stamp-demo"] != "unverified" || got["plain-demo"] != "verified" {
		t.Fatalf("list -json verification: %v", got)
	}
	// A suite filter line selects the same set.
	suite := filepath.Join(t.TempDir(), "needs-validation.txt")
	if err := os.WriteFile(suite, []byte("# targets nobody has run\n-unverified\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = run(t, stampEngine(t), "-T", root, "stamp", "-expose", "host", "-dry-run", "-f", suite)
	if code != ExitOK || !strings.Contains(out, "verified stamp-demo") || strings.Contains(out, "plain-demo") {
		t.Fatalf("stamp -f with a -unverified filter line: %d\n%s\n%s", code, out, errOut)
	}
	code, out, _ = run(t, nil, "-T", root, "info", "stamp-demo")
	if code != ExitOK || !strings.Contains(out, "verified     no -- nobody has run") {
		t.Fatalf("info: %d\n%s", code, out)
	}
	code, out, _ = run(t, nil, "-T", root, "-json", "info", "plain-demo")
	if code != ExitOK || !strings.Contains(out, `"verification": "verified"`) {
		t.Fatalf("info -json: %d\n%s", code, out)
	}
}
