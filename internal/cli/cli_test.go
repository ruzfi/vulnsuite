package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// seedHostTarget injects a running grafana container published on hostIP:hostPort.
func seedHostTarget(fe *enginetest.Fake, hostIP string, hostPort int) {
	name := contract.ContainerNamePrefix + "grafana-8.3.0-cve-2021-43798-vulnerable"
	fe.Containers[name] = &enginetest.Container{
		ID: "c1", Running: true, IP: "172.17.0.2",
		Spec: engine.ContainerSpec{
			Name:  name,
			Ports: []engine.PortBinding{{HostIP: hostIP, HostPort: hostPort, ContainerPort: 3000, Protocol: "tcp"}},
		},
	}
}

func fixtures(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "templates"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func run(t *testing.T, fe *enginetest.Fake, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	// Main builds its own Global; inject the fake through a wrapper command list.
	code := mainWithEngine(context.Background(), fe, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestListAndValidate(t *testing.T) {
	// Isolate scanner-dir resolution from the developer's machine: a real
	// ~/nuclei-templates or $NUCLEI_TEMPLATES otherwise makes `info` print the
	// template path and breaks the assertions below. CI has no such checkout.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("NUCLEI_TEMPLATES", "")
	root := fixtures(t)
	code, out, _ := run(t, nil, "-T", root, "list")
	if code != ExitOK || !strings.Contains(out, "grafana-8.3.0-cve-2021-43798") || !strings.Contains(out, "5 templates") {
		t.Fatalf("list: %d\n%s", code, out)
	}
	code, out, _ = run(t, nil, "list", "-T", root, "-tag", "iot")
	if code != ExitOK || strings.Count(out, "\n") > 5 || !strings.Contains(out, "iot-camera-auth-bypass") {
		t.Fatalf("list -tag: %d\n%s", code, out)
	}
	code, out, _ = run(t, nil, "-json", "-T", root, "list", "grafana")
	var rows []listRow
	if code != ExitOK || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 1 || rows[0].BuildKind != "image" {
		t.Fatalf("list -json: %d %s", code, out)
	}
	// unpinned bases are errors by default...
	code, out, _ = run(t, nil, "-T", root, "validate")
	if code != ExitFail || !strings.Contains(out, "unpinned-base") {
		t.Fatalf("validate: %d\n%s", code, out)
	}
	// ...and warnings with -allow-unpinned
	code, out, _ = run(t, nil, "-T", root, "validate", "-allow-unpinned")
	if code != ExitOK || !strings.Contains(out, "0 errors") {
		t.Fatalf("validate -allow-unpinned: %d\n%s", code, out)
	}
	code, _, _ = run(t, nil, "-T", root, "validate", "-allow-unpinned", "-strict")
	if code != ExitFail {
		t.Fatal("strict must fail on warnings")
	}
	code, _, errOut := run(t, nil, "-T", root, "validate", "-t", "nope")
	if code != ExitFail || !strings.Contains(errOut, "no template found") {
		t.Fatalf("bad selector: %d %s", code, errOut)
	}
	code, _, errOut = run(t, nil, "bogus")
	if code != ExitUsage || !strings.Contains(errOut, "unknown command") {
		t.Fatalf("unknown command: %d %s", code, errOut)
	}
	code, out, _ = run(t, nil, "-T", root, "info", "exposed-dotenv-file")
	if code != ExitOK || !strings.Contains(out, "nuclei:laravel-env  verified") || !strings.Contains(out, "verify http GET /.env") {
		t.Fatalf("info: %d\n%s", code, out)
	}
	code, out, _ = run(t, nil, "-T", root, "info", "grafana")
	if code != ExitOK || !strings.Contains(out, "detection gap") {
		t.Fatalf("info gap hint: %d\n%s", code, out)
	}
	code, out, _ = run(t, nil, "help", "build")
	if code != ExitOK || !strings.Contains(out, "-registry") {
		t.Fatalf("help: %d %s", code, out)
	}
}

func TestBuildAndImages(t *testing.T) {
	root := fixtures(t)
	fe := enginetest.New()
	code, out, errOut := run(t, fe, "-T", root, "build", "-t", "apache", "-t", "grafana", "-j", "2")
	if code != ExitOK {
		t.Fatalf("build: %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "4 ok, 0 failed") || len(fe.Builds) != 2 || len(fe.Pulls) != 3 {
		t.Fatalf("builds=%d pulls=%v\n%s", len(fe.Builds), fe.Pulls, out)
	}
	code, out, _ = run(t, fe, "-json", "-T", root, "build", "-t", "apache", "-state", "vulnerable", "-push", "-registry", "ghcr.io/ruzfi/vulnsuite")
	var res []buildResult
	if code != ExitOK || json.Unmarshal([]byte(out), &res) != nil || len(res) != 1 || res[0].Built || len(res[0].Pushed) != 2 {
		t.Fatalf("build -push: %d %s", code, out)
	}
	code, out, _ = run(t, fe, "-T", root, "images")
	if code != ExitOK || !strings.Contains(out, "apache-httpd-2.4.49-cve-2021-41773") {
		t.Fatalf("images: %d %s", code, out)
	}
	code, _, errOut = run(t, fe, "-T", root, "build", "-push")
	if code != ExitUsage || !strings.Contains(errOut, "-registry") {
		t.Fatalf("push without registry: %d %s", code, errOut)
	}
	fe.FailBuild = "boom"
	code, _, errOut = run(t, fe, "-T", root, "build", "-t", "iot", "-force")
	if code != ExitFail || !strings.Contains(errOut, "boom") {
		t.Fatalf("failed build: %d %s", code, errOut)
	}
}

func TestRunStopPs(t *testing.T) {
	root := fixtures(t)
	fe := enginetest.New()
	code, out, errOut := run(t, fe, "-T", root, "run", "patched", "-t", "grafana", "-detach", "-no-verify", "-ready-timeout", "1s")
	if code != ExitOK || !strings.Contains(out, "grafana-8.3.0-cve-2021-43798 [patched]") {
		t.Fatalf("run: %d\n%s\n%s", code, out, errOut)
	}
	if c := fe.Containers["vulnsuite-grafana-8.3.0-cve-2021-43798-patched"]; c == nil || c.Spec.Image != "grafana/grafana:8.3.1" {
		t.Fatalf("container: %+v", fe.Containers)
	}
	code, out, _ = run(t, fe, "-T", root, "ps")
	if code != ExitOK || !strings.Contains(out, "1 running") {
		t.Fatalf("ps: %d %s", code, out)
	}
	code, out, _ = run(t, fe, "-T", root, "targets", "-by", "alias")
	if code != ExitOK || !strings.Contains(out, "http://grafana-8.3.0-cve-2021-43798:3000") {
		t.Fatalf("targets: %d %s", code, out)
	}
	// concurrency cap counts what is already running
	code, _, errOut = run(t, fe, "-T", root, "run", "-t", "apache", "-detach", "-no-verify", "-ready-timeout", "1s", "-max-concurrent", "1")
	if code != ExitFail || !strings.Contains(errOut, "max concurrent") {
		t.Fatalf("cap: %d %s", code, errOut)
	}
	code, out, _ = run(t, fe, "-T", root, "stop")
	if code != ExitOK || !strings.Contains(out, "stopped 1 container") {
		t.Fatalf("stop: %d %s", code, out)
	}
	code, out, _ = run(t, fe, "-T", root, "ps")
	if code != ExitOK || !strings.Contains(out, "no targets running") {
		t.Fatalf("ps after stop: %d %s", code, out)
	}
}

func TestTargetsReportsBoundHostAddress(t *testing.T) {
	root := fixtures(t)

	// A port bound to a specific address (what -bind does for a remote daemon)
	// must be reported at that address by both the auto default and -by host, so
	// the URL works from the scanner's machine.
	fe := enginetest.New()
	seedHostTarget(fe, "203.0.113.9", 49154)
	code, out, _ := run(t, fe, "-T", root, "targets")
	if code != ExitOK || !strings.Contains(out, "http://203.0.113.9:49154") {
		t.Fatalf("targets auto: %d %s", code, out)
	}
	code, out, _ = run(t, fe, "-T", root, "targets", "-by", "host")
	if code != ExitOK || !strings.Contains(out, "http://203.0.113.9:49154") {
		t.Fatalf("targets -by host: %d %s", code, out)
	}

	// A port bound to all interfaces is reported as loopback, which a local
	// scanner can dial.
	fe = enginetest.New()
	seedHostTarget(fe, "0.0.0.0", 49155)
	code, out, _ = run(t, fe, "-T", root, "targets", "-by", "host")
	if code != ExitOK || !strings.Contains(out, "http://127.0.0.1:49155") {
		t.Fatalf("targets 0.0.0.0: %d %s", code, out)
	}
}
