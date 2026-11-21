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
	vo := c.Metadata.VerifiedOn.Latest()
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

// Stamping on a second host keeps the first host's run; list, info and
// list -json show both.
func TestStampOnSecondHostKeepsFirst(t *testing.T) {
	root, path := stampRoot(t)
	if code, out, errOut := run(t, stampEngine(t), "-T", root, "stamp", "-expose", "host", "-t", "stamp-demo"); code != ExitOK ||
		!strings.Contains(out, "stamped stamp-demo on linux/amd64") {
		t.Fatalf("stamp on amd64: %d\n%s\n%s", code, out, errOut)
	}
	arm := stampEngine(t)
	arm.HostInfo.Arch = "arm64"
	if code, out, errOut := run(t, arm, "-T", root, "stamp", "-expose", "host", "-t", "stamp-demo"); code != ExitOK ||
		!strings.Contains(out, "stamped stamp-demo on linux/arm64") ||
		!strings.Contains(out, "note: verified_on now records runs on 2 hosts, written as a list; vulnsuite v0.5.0 and older cannot read that form") {
		t.Fatalf("stamp on arm64: %d\n%s\n%s", code, out, errOut)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := contract.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, r := range c.Metadata.VerifiedOn {
		hosts = append(hosts, r.Host)
	}
	if strings.Join(hosts, ",") != "linux/amd64,linux/arm64" {
		t.Fatalf("runs on %v:\n%s", hosts, data)
	}
	code, out, _ := run(t, nil, "-T", root, "info", "stamp-demo")
	if code != ExitOK || !strings.Contains(out, "last runs") || !strings.Contains(out, "on linux/amd64 with avx512vbmi") ||
		!strings.Contains(out, "on linux/arm64 with avx512vbmi") {
		t.Fatalf("info: %d\n%s", code, out)
	}
	code, out, _ = run(t, nil, "-T", root, "-json", "list", "-verified")
	var rows []struct {
		ID           string                `json:"id"`
		VerifiedOn   []contract.VerifiedOn `json:"verified_on"`
		VerifiedRuns []contract.VerifiedOn `json:"verified_runs"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &rows) != nil {
		t.Fatalf("list -json: %d\n%s", code, out)
	}
	found := false
	for _, r := range rows {
		found = found || r.ID == "stamp-demo" && len(r.VerifiedOn) == 2 && len(r.VerifiedRuns) == 2
	}
	if !found {
		t.Fatalf("list -json must carry both runs of stamp-demo as an array:\n%s", out)
	}
	if _, vout, _ := run(t, nil, "-T", root, "validate", "-t", "stamp-demo"); strings.Contains(vout, "verified-on") {
		t.Fatalf("validate after two stamps:\n%s", vout)
	}
}

// #137: an image for another platform than the daemon's, run without any
// requires asking for emulation, is recorded with its platform, not as a
// native run on the host.
func TestStampRecordsEmulationWithoutRequires(t *testing.T) {
	root, _ := stampRoot(t)
	path := filepath.Join(root, "misc", "plain-demo", "contract.yaml")
	fe := stampEngine(t)
	fe.HostInfo.Arch = "arm64"
	fe.Images["busybox:1"] = true
	fe.ImagePlatforms["busybox:1"] = "linux/amd64"
	code, out, errOut := run(t, fe, "-T", root, "stamp", "-expose", "host", "-no-pull", "-t", "plain-demo")
	if code != ExitOK || !strings.Contains(out, "stamped plain-demo on linux/arm64 running linux/amd64:") {
		t.Fatalf("stamp: %d\n%s\n%s", code, out, errOut)
	}
	data, _ := os.ReadFile(path)
	c, err := contract.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if vo := c.Metadata.VerifiedOn.Latest(); vo == nil || vo.Host != "linux/arm64" || vo.Platform != "linux/amd64" {
		t.Fatalf("verified_on %+v\n%s", vo, data)
	}
	// A native image records no platform.
	fe = stampEngine(t)
	fe.Images["busybox:1"] = true
	fe.ImagePlatforms["busybox:1"] = "linux/amd64"
	if code, out, errOut := run(t, fe, "-T", root, "stamp", "-expose", "host", "-no-pull", "-t", "plain-demo"); code != ExitOK ||
		!strings.Contains(out, "stamped plain-demo on linux/amd64:") {
		t.Fatalf("native stamp: %d\n%s\n%s", code, out, errOut)
	}
}

// #137: the file changed during the run (an edited probe) is not stamped;
// list -json and info -json carry verified_runs as an array even with no run.
func TestStampRefusesContractChangedDuringRun(t *testing.T) {
	root, path := stampRoot(t)
	fe := stampEngine(t)
	exec := fe.ExecFn
	edited := false
	fe.ExecFn = func(container, command string) (int, string, error) {
		if !edited {
			edited = true
			data, _ := os.ReadFile(path)
			_ = os.WriteFile(path, []byte(strings.Replace(string(data), "^patched$", "^patched!$", 1)), 0o644)
		}
		return exec(container, command)
	}
	code, out, errOut := run(t, fe, "-T", root, "stamp", "-expose", "host", "-t", "stamp-demo")
	if code == ExitOK || !strings.Contains(errOut, "the contract changed since it was loaded") {
		t.Fatalf("stamp: %d\n%s\n%s", code, out, errOut)
	}
	if data, _ := os.ReadFile(path); strings.Contains(string(data), "verified_on") {
		t.Fatalf("stamped a changed contract:\n%s", data)
	}
	code, out, _ = run(t, nil, "-T", root, "-json", "info", "plain-demo")
	if code != ExitOK || !strings.Contains(out, `"verified_runs": []`) {
		t.Fatalf("info -json: %d\n%s", code, out)
	}
}
