package cli

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/runner"
)

// Regression tests for #43: -json output and exit codes a script can rely on.

// #43 item 1: the URL list is the output of `targets`; -q must not drop it.
func TestTargetsQuietStillPrintsURLs(t *testing.T) {
	root := fixtures(t)
	fe := enginetest.New()
	seedHostTarget(fe, "127.0.0.1", 49154)
	code, out, errOut := run(t, fe, "-q", "-T", root, "targets")
	if code != ExitOK || !strings.Contains(out, "http://127.0.0.1:49154") {
		t.Fatalf("-q targets: %d\nstdout: %q\nstderr: %s", code, out, errOut)
	}
	if strings.Contains(out, "Scan just these") {
		t.Fatalf("-q should silence the hint:\n%s", out)
	}
}

// #43 item 2: -json with -file still writes the file.
func TestTargetsJSONWritesFile(t *testing.T) {
	root := fixtures(t)
	fe := enginetest.New()
	seedHostTarget(fe, "127.0.0.1", 49154)
	file := filepath.Join(t.TempDir(), "t.txt")
	code, out, errOut := run(t, fe, "-json", "-T", root, "targets", "-file", file)
	if code != ExitOK {
		t.Fatalf("targets -json -file: %d\n%s\n%s", code, out, errOut)
	}
	var pairs []map[string]string
	if err := json.Unmarshal([]byte(out), &pairs); err != nil || len(pairs) != 1 {
		t.Fatalf("stdout is not the JSON list: %v\n%s", err, out)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("-file not written with -json: %v", err)
	}
	if strings.TrimSpace(string(data)) != "http://127.0.0.1:49154" {
		t.Fatalf("file: %q", data)
	}
}

// #43 item 3: stop -json -prune-net removes the network and says so.
func TestStopJSONPrunesNetwork(t *testing.T) {
	root := fixtures(t)
	fe := enginetest.New()
	seedHostTarget(fe, "127.0.0.1", 49154)
	fe.Networks[runner.DefaultNetwork] = engine.NetworkSpec{Name: runner.DefaultNetwork, Labels: map[string]string{engine.LabelManaged: "true"}}
	code, out, errOut := run(t, fe, "-json", "-T", root, "stop", "-prune-net")
	if code != ExitOK {
		t.Fatalf("stop: %d\n%s\n%s", code, out, errOut)
	}
	var res struct {
		Removed        []string `json:"removed"`
		NetworkRemoved *bool    `json:"network_removed"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if len(res.Removed) != 1 || res.NetworkRemoved == nil || !*res.NetworkRemoved {
		t.Fatalf("stop -json -prune-net: %s", out)
	}
	if _, ok := fe.Networks[runner.DefaultNetwork]; ok {
		t.Fatal("network not removed")
	}

	// Nothing running, no -prune-net: [] (not null) and network_removed false.
	code, out, _ = run(t, fe, "-json", "-T", root, "stop")
	if code != ExitOK || !strings.Contains(out, `"removed": []`) || !strings.Contains(out, `"network_removed": false`) {
		t.Fatalf("empty stop -json: %d %s", code, out)
	}
}

// listIDs runs `list -json` with args and returns the sorted ids.
func listIDs(t *testing.T, root string, args ...string) []string {
	t.Helper()
	code, out, errOut := run(t, nil, append([]string{"-json", "-T", root, "list"}, args...)...)
	var rows []listRow
	if code != ExitOK || json.Unmarshal([]byte(out), &rows) != nil {
		t.Fatalf("list %v: %d\n%s\n%s", args, code, out, errOut)
	}
	var ids []string
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return ids
}

// buildIDs runs `build -json -state vulnerable` with args and returns the
// sorted ids built.
func buildIDs(t *testing.T, root string, args ...string) []string {
	t.Helper()
	code, out, errOut := run(t, enginetest.New(), append([]string{"-json", "-T", root, "build", "-state", "vulnerable"}, args...)...)
	var res []buildResult
	if code != ExitOK || json.Unmarshal([]byte(out), &res) != nil {
		t.Fatalf("build %v: %d\n%s\n%s", args, code, out, errOut)
	}
	var ids []string
	for _, r := range res {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return ids
}

// #43 item 5: a filter selects the same set on list as on build/run. Per #36
// a filter that matches a variant member includes it regardless of collapse;
// list now follows that rule too instead of hiding the members.
func TestFilterSetMatchesListAndBuild(t *testing.T) {
	isolateHome(t)
	root := groupFixtures(t)
	want := []string{"php2shell-base", "php2shell-chunked", "php2shell-waf", "standalone"}
	if got := listIDs(t, root, "-category", "web-apps"); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("list -category web-apps = %v, want %v", got, want)
	}
	if got := buildIDs(t, root, "-category", "web-apps"); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("build -category web-apps = %v, want %v", got, want)
	}
	// -all and a bare list still collapse each group to its primary.
	collapsed := []string{"php2shell-base", "redis-rce", "standalone"}
	if got := listIDs(t, root); strings.Join(got, ",") != strings.Join(collapsed, ",") {
		t.Fatalf("bare list = %v, want %v", got, collapsed)
	}
	if got := buildIDs(t, root, "-all"); strings.Join(got, ",") != strings.Join(collapsed, ",") {
		t.Fatalf("build -all = %v, want %v", got, collapsed)
	}
	// With a selector, list's filters narrow what it selected: a group handle
	// still resolves to its primary.
	if got := listIDs(t, root, "php2shell", "-category", "web-apps"); strings.Join(got, ",") != "php2shell-base" {
		t.Fatalf("list php2shell -category web-apps = %v", got)
	}
}

// #43 item 6: a template that fails to load is reported and fails build (as
// it fails run), both on -all and through the filter path.
func TestBrokenTemplateFailsBuildAndRun(t *testing.T) {
	isolateHome(t)
	root := groupFixtures(t)
	broken := filepath.Join(root, "web-apps", "broken-one", "contract.yaml")
	writeFile(t, broken, "apiVersion: vulnsuite/v1\nkind: Target\nmetadata:\n  id: broken-one\n  bogus_field: 1\n")

	for _, args := range [][]string{{"-all"}, {"-category", "web-apps"}} {
		fe := enginetest.New()
		code, out, errOut := run(t, fe, append([]string{"-T", root, "build", "-state", "vulnerable"}, args...)...)
		if code != ExitFail || !strings.Contains(errOut, "broken-one") || !strings.Contains(errOut, "1 build(s) failed") {
			t.Fatalf("build %v with a broken template: %d\n%s\n%s", args, code, out, errOut)
		}
		if len(fe.Pulls) == 0 {
			t.Fatalf("build %v should still resolve the good templates", args)
		}
		code, out, errOut = run(t, enginetest.New(), append([]string{"-json", "-T", root, "build", "-state", "vulnerable"}, args...)...)
		var res []buildResult
		if code != ExitFail || json.Unmarshal([]byte(out), &res) != nil {
			t.Fatalf("build -json %v: %d\n%s\n%s", args, code, out, errOut)
		}
		found := false
		for _, r := range res {
			if r.ID == "broken-one" && r.Error != "" {
				found = true
			}
		}
		if !found {
			t.Fatalf("build -json %v: no error entry for the broken template:\n%s", args, out)
		}
	}

	fe := enginetest.New()
	code, out, errOut := run(t, fe, "-T", root, "run", "-category", "web-apps", "-detach", "-no-verify")
	if code != ExitFail || !strings.Contains(errOut, "failed to load") || len(fe.Containers) != 0 {
		t.Fatalf("run -category with a broken template: %d\n%s\n%s", code, out, errOut)
	}
}

// #43 item 7: bad -expose, -max-concurrent and -by are usage errors, caught
// before anything is pulled, built or started.
func TestRunFlagValidation(t *testing.T) {
	root := fixtures(t)
	for _, args := range [][]string{
		{"-expose", "hots"},
		{"-max-concurrent", "0"},
		{"-max-concurrent", "-3"},
		{"-host-port", "3000"}, // internal mode publishes nothing
		{"-expose", "host", "-host-port", "70000"},
	} {
		fe := enginetest.New()
		code, out, errOut := run(t, fe, append([]string{"-T", root, "run", "-t", "grafana", "-detach", "-no-verify"}, args...)...)
		if code != ExitUsage || !strings.Contains(errOut, "usage:") {
			t.Fatalf("run %v: want usage exit 2, got %d\n%s\n%s", args, code, out, errOut)
		}
		if len(fe.Pulls) != 0 || len(fe.Builds) != 0 || len(fe.Containers) != 0 {
			t.Fatalf("run %v touched the engine: pulls=%v builds=%d containers=%d", args, fe.Pulls, len(fe.Builds), len(fe.Containers))
		}
	}
	fe := enginetest.New()
	seedHostTarget(fe, "127.0.0.1", 49154)
	code, out, errOut := run(t, fe, "-T", root, "targets", "-by", "bogus")
	if code != ExitUsage || out != "" {
		t.Fatalf("targets -by bogus: %d\n%s\n%s", code, out, errOut)
	}
}

// freePort returns a currently unused TCP port on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// #43 item 8: a host-port pin with several targets is a usage error, not a
// silent drop; and it is judged after the requires skips, so a batch that
// ends up with one target keeps its pin.
func TestHostPortPinWithSeveralTargets(t *testing.T) {
	root := lifecycleTemplates(t, map[string]string{"aaa-windows-only": "requires: { host_os: [windows] }"}, "foo", "foo-bar", "aaa-windows-only")

	fe := lifecycleFake(t)
	code, out, errOut := run(t, fe, "-T", root, "run", "-t", "foo", "-t", "foo-bar", "-expose", "host", "-host-port", "3000",
		"-detach", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir())
	if code != ExitUsage || !strings.Contains(errOut, "-host-port") || len(fe.Containers) != 0 {
		t.Fatalf("pin with two targets: %d\n%s\n%s", code, out, errOut)
	}
	code, out, errOut = run(t, fe, "-T", root, "run", "-t", "foo", "-t", "foo-bar", "-expose", "host", "-host-port-map", "8080=3001",
		"-detach", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir())
	if code != ExitUsage || !strings.Contains(errOut, "-host-port-map") || len(fe.Containers) != 0 {
		t.Fatalf("pin map with two targets: %d\n%s\n%s", code, out, errOut)
	}

	port := freePort(t)
	fe = lifecycleFake(t)
	code, out, errOut = run(t, fe, "-T", root, "run", "-t", "aaa-windows-only", "-t", "foo", "-expose", "host", "-bind", "127.0.0.1",
		"-host-port", strconv.Itoa(port), "-detach", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir())
	if code != ExitOK {
		t.Fatalf("one runnable target after skips: %d\n%s\n%s", code, out, errOut)
	}
	c := fe.Containers[contract.ContainerNamePrefix+"foo-vulnerable"]
	if c == nil || len(c.Spec.Ports) == 0 || c.Spec.Ports[0].HostPort != port {
		t.Fatalf("pin dropped after skips: %+v", c)
	}
}

// #43 item 10: empty lists are [], not null.
func TestJSONEmptyListsAreArrays(t *testing.T) {
	isolateHome(t)
	root := fixtures(t)
	code, out, _ := run(t, nil, "-json", "-T", root, "list", "-tag", "nonexistent")
	if code != ExitOK || strings.TrimSpace(out) != "[]" {
		t.Fatalf("list -json no match: %d %q", code, out)
	}
	code, out, _ = run(t, enginetest.New(), "-json", "-T", root, "images")
	if code != ExitOK || strings.TrimSpace(out) != "[]" {
		t.Fatalf("images -json none: %d %q", code, out)
	}
}

// #43 item 10: version -json reports the same version the text output shows.
func TestVersionJSONMatchesText(t *testing.T) {
	_, text, _ := run(t, nil, "version")
	first := strings.SplitN(text, "\n", 2)[0]
	_, out, _ := run(t, nil, "-json", "version")
	var v map[string]string
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "vulnsuite "+v["version"]) || v["version"] != resolvedVersion() {
		t.Fatalf("text %q vs json version %q", first, v["version"])
	}

	// A release build's -ldflags version is reported as is.
	old := Version
	Version = "v9.8.7"
	defer func() { Version = old }()
	_, out, _ = run(t, nil, "-json", "version")
	if !strings.Contains(out, `"version": "v9.8.7"`) {
		t.Fatalf("version -json: %s", out)
	}
}

// #43 item 10: images -rm emits JSON and fails when a removal fails.
func TestImagesRmReportsFailures(t *testing.T) {
	fe := enginetest.New()
	good := contract.ImageRepoPrefix + "/a:vulnerable-1"
	bad := contract.ImageRepoPrefix + "/b:vulnerable-2"
	fe.Images[good], fe.Images[bad] = true, true
	fe.ImageRemoveFn = func(ref string) error {
		if ref == bad {
			return errors.New("image is in use")
		}
		return nil
	}
	code, out, errOut := run(t, fe, "-json", "images", "-rm")
	if code != ExitFail || !strings.Contains(errOut, "in use") {
		t.Fatalf("images -rm with a failure: %d\n%s\n%s", code, out, errOut)
	}
	var res struct {
		Removed []string `json:"removed"`
		Failed  []struct {
			Ref   string `json:"ref"`
			Error string `json:"error"`
		} `json:"failed"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("images -rm -json: %v\n%s", err, out)
	}
	if len(res.Removed) != 1 || res.Removed[0] != good || len(res.Failed) != 1 || res.Failed[0].Ref != bad {
		t.Fatalf("images -rm -json: %s", out)
	}
	// All removed: exit 0, failed is [].
	fe.ImageRemoveFn = nil
	code, out, _ = run(t, fe, "-json", "images", "-rm")
	if code != ExitOK || !strings.Contains(out, `"failed": []`) {
		t.Fatalf("images -rm clean: %d %s", code, out)
	}
}

// #43 item 10: a bare invocation is a usage error; its help goes to stderr.
func TestBareInvocationHelpOnStderr(t *testing.T) {
	for _, args := range [][]string{nil, {"-json"}} {
		code, out, errOut := run(t, nil, args...)
		if code != ExitUsage || out != "" || !strings.Contains(errOut, "usage: vulnsuite") {
			t.Fatalf("vulnsuite %v: %d\nstdout: %q\nstderr: %s", args, code, out, errOut)
		}
	}
	// Asked-for help is still on stdout, exit 0.
	code, out, _ := run(t, nil, "help")
	if code != ExitOK || !strings.Contains(out, "usage: vulnsuite") {
		t.Fatalf("help: %d %s", code, out)
	}
}

// #94 item 5: run -json prints its array on early failures too (here: a
// template fails to load, and nothing comes up), so a pipeline always gets
// JSON; the exit code still says it failed.
func TestRunJSONOnEarlyFailure(t *testing.T) {
	root, _ := brokenFixtures(t)
	fe := enginetest.New()
	code, out, errOut := run(t, fe, "-json", "-T", root, "run", "-t", "grafana", "-detach", "-no-verify", "-ready-timeout", "1s")
	var handles []map[string]any
	if code != ExitFail || json.Unmarshal([]byte(out), &handles) != nil || handles == nil || len(handles) != 0 {
		t.Fatalf("run -json with a load error: %d\nstdout: %q\nstderr: %s", code, out, errOut)
	}

	fe = enginetest.New()
	fe.FailPull = true // grafana is an image base: nothing comes up
	code, out, errOut = run(t, fe, "-json", "-T", fixtures(t), "run", "-t", "grafana", "-detach", "-no-verify", "-ready-timeout", "1s")
	handles = nil
	if code != ExitFail || !strings.Contains(errOut, "nothing came up") || json.Unmarshal([]byte(out), &handles) != nil || handles == nil || len(handles) != 0 {
		t.Fatalf("run -json with nothing up: %d\nstdout: %q\nstderr: %s", code, out, errOut)
	}
}

// #94 item 5: targets -json prints [] with nothing running, like ps -json.
func TestTargetsJSONWithNothingRunning(t *testing.T) {
	code, out, errOut := run(t, enginetest.New(), "-json", "-T", fixtures(t), "targets")
	var pairs []map[string]string
	if code != ExitFail || json.Unmarshal([]byte(out), &pairs) != nil || pairs == nil || len(pairs) != 0 {
		t.Fatalf("targets -json: %d\nstdout: %q\nstderr: %s", code, out, errOut)
	}
	// A usage error still prints no JSON.
	code, out, _ = run(t, enginetest.New(), "-json", "-T", fixtures(t), "targets", "-by", "bogus")
	if code != ExitUsage || out != "" {
		t.Fatalf("targets -json -by bogus: %d %q", code, out)
	}
}
