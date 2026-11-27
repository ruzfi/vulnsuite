package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/runner"
)

// #153 item 1: stamp runs each state by replacing its container, so a target
// the user has running would be torn down. It refuses instead, -dry-run too,
// and leaves the target running.
func TestStampRefusesRunningTarget(t *testing.T) {
	root, _ := stampRoot(t)
	fe := stampEngine(t)
	if code, out, errOut := run(t, fe, "-T", root, "run", "-t", "plain-demo", "-expose", "host", "-detach", "-no-verify"); code != ExitOK {
		t.Fatalf("run: %d\n%s\n%s", code, out, errOut)
	}
	for _, extra := range [][]string{{"-dry-run"}, nil} {
		args := append([]string{"-T", root, "stamp", "-expose", "host", "-t", "plain-demo"}, extra...)
		code, out, errOut := run(t, fe, args...)
		if code != ExitFail || !strings.Contains(errOut, "plain-demo [vulnerable] already running") ||
			!strings.Contains(errOut, "vulnsuite stop -t plain-demo") {
			t.Fatalf("stamp %v over a running target: %d\n%s\n%s", extra, code, out, errOut)
		}
	}
	code, out, _ := run(t, fe, "-json", "ps")
	var rows []runner.Target
	if code != ExitOK || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 1 || rows[0].ID != "plain-demo" {
		t.Fatalf("the running target must survive the refused stamp: %d\n%s", code, out)
	}
	// -json still prints the (empty) result list.
	code, out, _ = run(t, fe, "-T", root, "-json", "stamp", "-expose", "host", "-dry-run", "-t", "plain-demo")
	if code != ExitFail || strings.TrimSpace(out) != "[]" {
		t.Fatalf("stamp -json over a running target: %d %q", code, out)
	}
	// Once it is stopped, stamp runs.
	if code, _, errOut := run(t, fe, "stop"); code != ExitOK {
		t.Fatalf("stop: %d %s", code, errOut)
	}
	if code, out, errOut := run(t, fe, "-T", root, "stamp", "-expose", "host", "-dry-run", "-t", "plain-demo"); code != ExitOK {
		t.Fatalf("stamp after stop: %d\n%s\n%s", code, out, errOut)
	}
}

// #153 item 2: stamp checks -host-port-map as run does.
func TestStampChecksHostPortMap(t *testing.T) {
	root, _ := stampRoot(t)
	code, out, errOut := run(t, stampEngine(t), "-T", root, "stamp", "-dry-run", "-expose", "host", "-host-port-map", "9999=45678", "-t", "plain-demo")
	if code != ExitUsage || !strings.Contains(errOut, "does not publish container port 9999") {
		t.Fatalf("stamp with a pin on an unpublished port: %d\n%s\n%s", code, out, errOut)
	}
	code, out, errOut = run(t, stampEngine(t), "-T", root, "stamp", "-dry-run", "-expose", "host", "-host-port-map", "80=45678", "-t", "plain-demo")
	if code != ExitOK {
		t.Fatalf("stamp with a valid pin: %d\n%s\n%s", code, out, errOut)
	}
}

// runReal is run without an injected engine: commands connect as the binary
// does (run's nil *Fake would be a non-nil engine).
func runReal(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := mainWithEngine(context.Background(), nil, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// hungListener accepts connections and never answers.
func hungListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
		for _, c := range conns {
			c.Close()
		}
	})
	return "tcp://" + ln.Addr().String()
}

// closedPort is a tcp:// address nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "tcp://" + addr
}

// #153 item 3: a daemon that accepts but never answers does not hang either
// engine: the first Ping has a deadline.
func TestEnginePingDeadline(t *testing.T) {
	old := pingTimeout
	pingTimeout = 300 * time.Millisecond
	t.Cleanup(func() { pingTimeout = old })
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_API_VERSION", "")
	host := hungListener(t)
	for _, kind := range []string{"api", "sdk"} {
		start := time.Now()
		code, _, errOut := runReal(t, "-engine", kind, "-docker-host", host, "ps")
		if code != ExitFail {
			t.Errorf("-engine %s ps against a hung daemon: %d %s", kind, code, errOut)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("-engine %s took %v", kind, d)
		}
	}
}

// #153 item 4: an unknown -engine or $VULNSUITE_ENGINE is a usage error for
// every command, before anything runs.
func TestUnknownEngineIsUsageError(t *testing.T) {
	root := fixtures(t)
	for _, args := range [][]string{
		{"-engine", "bogus", "ps"},
		{"-engine", "bogus", "-T", root, "list"},
		{"-T", root, "list", "-engine", "bogus"},
		{"-engine", "bogus", "-version"},
	} {
		if code, _, errOut := run(t, nil, args...); code != ExitUsage || !strings.Contains(errOut, `unknown engine "bogus"`) {
			t.Errorf("%v: %d %s", args, code, errOut)
		}
	}
	t.Setenv("VULNSUITE_ENGINE", "bogus")
	if code, _, errOut := run(t, nil, "version"); code != ExitUsage || !strings.Contains(errOut, "$VULNSUITE_ENGINE") {
		t.Errorf("VULNSUITE_ENGINE=bogus version: %d %s", code, errOut)
	}
	// An explicit valid -engine overrides the variable.
	if code, _, errOut := run(t, nil, "-engine", "api", "version"); code != ExitOK {
		t.Errorf("-engine api version: %d %s", code, errOut)
	}
}

// #153 item 6: stop -network without -prune-net would be ignored (#113:
// refused); with it, a network vulnsuite did not create is left alone.
func TestStopNetworkFlag(t *testing.T) {
	fe := enginetest.New()
	if code, _, errOut := run(t, fe, "stop", "-network", "user-net"); code != ExitUsage || !strings.Contains(errOut, "-prune-net") {
		t.Fatalf("stop -network without -prune-net: %d %s", code, errOut)
	}
	fe.Networks["user-net"] = engine.NetworkSpec{Name: "user-net"}
	code, out, errOut := run(t, fe, "-json", "stop", "-prune-net", "-network", "user-net")
	if code != ExitOK || !strings.Contains(errOut, "not created by vulnsuite") || !strings.Contains(out, `"network_removed": false`) {
		t.Fatalf("stop -prune-net -network user-net: %d\n%s\n%s", code, out, errOut)
	}
	if _, ok := fe.Networks["user-net"]; !ok {
		t.Fatal("an unmanaged network was removed")
	}
}

// #153 item 7: with the engine unreachable, ps, stop and host -json still
// print valid JSON on stdout (and fail).
func TestJSONOnUnreachableEngine(t *testing.T) {
	t.Setenv("DOCKER_TLS_VERIFY", "")
	host := closedPort(t)
	for _, tc := range []struct {
		cmd  string
		want func(any) bool
	}{
		{"ps", func(v any) bool { l, ok := v.([]any); return ok && len(l) == 0 }},
		{"stop", func(v any) bool {
			m, ok := v.(map[string]any)
			l, lok := m["removed"].([]any)
			return ok && lok && len(l) == 0 && m["network_removed"] == false
		}},
		{"host", func(v any) bool { m, ok := v.(map[string]any); s, _ := m["error"].(string); return ok && s != "" }},
	} {
		code, out, errOut := runReal(t, "-json", "-engine", "api", "-docker-host", host, tc.cmd)
		var v any
		if code != ExitFail || json.Unmarshal([]byte(out), &v) != nil || !tc.want(v) {
			t.Errorf("%s -json, engine unreachable: %d\nstdout: %s\nstderr: %s", tc.cmd, code, out, errOut)
		}
	}
}

// #153 item 7: info -json declared is [] without detected_by; -json -version
// prints what -json version does.
func TestInfoDeclaredAndJSONVersion(t *testing.T) {
	root, _ := stampRoot(t)
	t.Setenv("NUCLEI_TEMPLATES", t.TempDir())
	code, out, errOut := run(t, nil, "-T", root, "-json", "info", "plain-demo")
	if code != ExitOK || !strings.Contains(out, `"declared": []`) {
		t.Fatalf("info -json: %d\n%s\n%s", code, out, errOut)
	}
	_, a, _ := run(t, nil, "-T", root, "-json", "-version")
	_, b, _ := run(t, nil, "-T", root, "-json", "version")
	var v map[string]any
	if a != b || json.Unmarshal([]byte(a), &v) != nil || v["version"] == nil {
		t.Fatalf("-json -version = %q, -json version = %q", a, b)
	}
}
