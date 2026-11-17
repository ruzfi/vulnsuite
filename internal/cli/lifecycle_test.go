package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

const lifecycleTemplate = `apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: ID
  summary: lifecycle fixture
  vuln_refs: [VS-TEST-LIFECYCLE]
  severity: low
  references: [https://example.invalid]
  detection: custom-only
base:
  kind: image
  image: example/app:1
EXTRA
service:
  ports: [ { container: 8080, protocol: http } ]
states:
  vulnerable: {}
  patched:
    environment: { MODE: patched }
`

// lifecycleTemplates writes image-kind templates into a fresh root; extra maps
// an id to top-level YAML (e.g. requires) added to its contract.
func lifecycleTemplates(t *testing.T, extra map[string]string, ids ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, id := range ids {
		dir := filepath.Join(root, "misc", id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		y := strings.Replace(strings.Replace(lifecycleTemplate, "ID", id, 1), "EXTRA", extra[id], 1)
		if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(y), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// lifecycleFake is a fake whose started containers answer on their published
// host ports, so host-mode targets come up ready.
func lifecycleFake(t *testing.T) *enginetest.Fake {
	fe := enginetest.New()
	fe.Images["example/app:1"] = true
	serveOnPublishedPorts(t, fe, "HTTP/1.0 200 OK\r\n\r\nok")
	return fe
}

// #42 item 1: stop -t foo leaves foo-bar running.
func TestStopSelectorIsExact(t *testing.T) {
	root := lifecycleTemplates(t, nil, "foo", "foo-bar")
	fe := lifecycleFake(t)
	for _, id := range []string{"foo", "foo-bar"} {
		if code, out, errOut := run(t, fe, "-T", root, "run", "-t", id, "-expose", "host", "-detach", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir()); code != ExitOK {
			t.Fatalf("run %s: %d\n%s\n%s", id, code, out, errOut)
		}
	}
	code, out, errOut := run(t, fe, "-T", root, "stop", "-t", "foo")
	if code != ExitOK || !strings.Contains(out, "stopped 1 container") || strings.Contains(out, "foo-bar") {
		t.Fatalf("stop -t foo: %d\n%s\n%s", code, out, errOut)
	}
	if fe.Containers["vulnsuite-foo-bar-vulnerable"] == nil {
		t.Fatal("stop -t foo removed foo-bar")
	}
}

// #42 item 7: a target skipped for its requires does not take a
// -max-concurrent slot.
func TestMaxConcurrentAfterSkips(t *testing.T) {
	root := lifecycleTemplates(t, map[string]string{"aaa-windows-only": "requires: { host_os: [windows] }"}, "aaa-windows-only", "bbb-runs")
	fe := lifecycleFake(t)
	code, out, errOut := run(t, fe, "-T", root, "run", "-t", "aaa-windows-only", "-t", "bbb-runs", "-max-concurrent", "1",
		"-expose", "host", "-detach", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir())
	if code != ExitOK || fe.Containers["vulnsuite-bbb-runs-vulnerable"] == nil {
		t.Fatalf("the free slot was not used: %d\n%s\n%s", code, out, errOut)
	}
	if strings.Contains(out, "skipping 1") || !strings.Contains(out, "skip aaa-windows-only") {
		t.Fatalf("output: %s", out)
	}
}

// #42 item 7: a daemon error while counting running targets fails the run
// instead of bypassing the cap.
func TestMaxConcurrentRunningError(t *testing.T) {
	root := lifecycleTemplates(t, nil, "bbb-runs")
	fe := lifecycleFake(t)
	fe.ListErr = errors.New("daemon hiccup")
	code, out, errOut := run(t, fe, "-T", root, "run", "-t", "bbb-runs", "-max-concurrent", "1", "-expose", "host", "-detach", "-no-verify")
	if code == ExitOK || !strings.Contains(errOut, "daemon hiccup") || len(fe.Containers) != 0 {
		t.Fatalf("Running error ignored: %d\n%s\n%s", code, out, errOut)
	}
}

// #42 item 5a: Ctrl-C during startup stops the loop, tears down what started
// and reports the interruption rather than "N target(s) failed".
func TestRunInterruptedDuringStartup(t *testing.T) {
	root := lifecycleTemplates(t, nil, "aaa1", "aaa2", "aaa3")
	fe := lifecycleFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serve := fe.StartFn
	fe.StartFn = func(spec engine.ContainerSpec) error {
		if spec.Name == "vulnsuite-aaa2-vulnerable" {
			cancel() // Ctrl-C while aaa2 is starting
			return context.Canceled
		}
		return serve(spec)
	}
	var out, errOut bytes.Buffer
	code := mainWithEngine(ctx, fe, []string{"-T", root, "run", "-t", "aaa1", "-t", "aaa2", "-t", "aaa3",
		"-expose", "host", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir()}, &out, &errOut)
	if code == ExitOK {
		t.Fatalf("interrupted run exited 0:\n%s\n%s", out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "interrupted") || strings.Contains(errOut.String(), "target(s) failed") ||
		strings.Contains(errOut.String(), "could not run") || strings.Contains(out.String(), "Scan these") {
		t.Fatalf("cancellation not reported as such:\n%s\n%s", out.String(), errOut.String())
	}
	if strings.Contains(out.String(), "[aaa3]") {
		t.Fatalf("the loop went on after the interrupt:\n%s", out.String())
	}
	if len(fe.Containers) != 0 {
		t.Fatalf("interrupted run leaked %v", fe.Containers)
	}
}

// syncBuffer is a goroutine-safe writer that closes seen once want appears.
type syncBuffer struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	want string
	seen chan struct{}
	once sync.Once
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.buf.Write(p)
	if strings.Contains(b.buf.String(), b.want) {
		b.once.Do(func() { close(b.seen) })
	}
	return n, err
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// holdThenInterrupt runs a held (non-detached) batch, interrupts it once it is
// holding and returns the exit code and output.
func holdThenInterrupt(t *testing.T, fe *enginetest.Fake, root string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &syncBuffer{want: "Holding.", seen: make(chan struct{})}
	errOut := &syncBuffer{seen: make(chan struct{})}
	done := make(chan int, 1)
	go func() {
		done <- mainWithEngine(ctx, fe, []string{"-T", root, "run", "-t", "aaa1", "-expose", "host", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir()}, out, errOut)
	}()
	select {
	case <-out.seen:
	case <-time.After(30 * time.Second):
		t.Fatalf("never held:\n%s\n%s", out.String(), errOut.String())
	}
	cancel()
	select {
	case code := <-done:
		return code, out.String(), errOut.String()
	case <-time.After(30 * time.Second):
		t.Fatal("teardown hung")
	}
	return 0, "", ""
}

// #42 item 5b: teardown after Ctrl-C runs on a fresh context (the fake fails
// removals on a cancelled one) and removes the batch.
func TestHoldTeardownUsesFreshContext(t *testing.T) {
	root := lifecycleTemplates(t, nil, "aaa1")
	fe := lifecycleFake(t)
	code, out, errOut := holdThenInterrupt(t, fe, root)
	if code != ExitOK || len(fe.Containers) != 0 {
		t.Fatalf("teardown: %d left=%v\n%s\n%s", code, fe.Containers, out, errOut)
	}
}

// #42 item 5b: a removal that fails during teardown is reported and fails the
// command instead of exiting 0 silently.
func TestHoldTeardownReportsErrors(t *testing.T) {
	root := lifecycleTemplates(t, nil, "aaa1")
	fe := lifecycleFake(t)
	fe.RemoveFn = func(name string) error {
		// Only the teardown's removal fails: the container exists by then.
		if _, err := fe.ContainerInspect(context.Background(), name); err == nil {
			return errors.New("removal timed out")
		}
		return nil
	}
	code, out, errOut := holdThenInterrupt(t, fe, root)
	if code == ExitOK || !strings.Contains(errOut, "could not tear down aaa1") || !strings.Contains(errOut, "removal timed out") ||
		!strings.Contains(errOut, "vulnsuite stop") {
		t.Fatalf("teardown failure not reported: %d\n%s\n%s", code, out, errOut)
	}
}
