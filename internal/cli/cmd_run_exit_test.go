package cli

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// serveOnPublishedPorts makes the fake stand a "container" up for real: on
// start it listens on every published host port and answers each connection
// that sends something with reply.
func serveOnPublishedPorts(t *testing.T, fe *enginetest.Fake, reply string) {
	t.Helper()
	fe.StartFn = func(spec engine.ContainerSpec) error {
		for _, p := range spec.Ports {
			l, err := net.Listen("tcp", net.JoinHostPort(p.HostIP, strconv.Itoa(p.HostPort)))
			if err != nil {
				return err
			}
			t.Cleanup(func() { l.Close() })
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(2 * time.Second))
						buf := make([]byte, 4096)
						if n, _ := c.Read(buf); n > 0 {
							_, _ = c.Write([]byte(reply))
						}
					}(c)
				}
			}()
		}
		return nil
	}
}

// Regression for #40 item 1: a target whose verify fails must fail the run,
// and -json must still emit the handles.
func TestRunExitsNonZeroWhenVerifyFails(t *testing.T) {
	root := fixtures(t)
	fe := enginetest.New()
	// The vulnerable state expects +PONG; this one demands auth.
	serveOnPublishedPorts(t, fe, "-NOAUTH Authentication required.\r\n")
	code, out, errOut := run(t, fe, "-T", root, "run", "vulnerable", "-t", "redis-unauthenticated-access",
		"-expose", "host", "-bind", "127.0.0.1", "-detach", "-ready-timeout", "3s", "-nuclei-templates", t.TempDir())
	if code == ExitOK {
		t.Fatalf("run exited 0 although verify failed:\n%s\n%s", out, errOut)
	}
	if !strings.Contains(out, "verify: FAILED") || !strings.Contains(errOut, "verify failed") {
		t.Fatalf("output should report the failed verify:\n%s\n%s", out, errOut)
	}

	fe = enginetest.New()
	serveOnPublishedPorts(t, fe, "-NOAUTH Authentication required.\r\n")
	code, out, errOut = run(t, fe, "-T", root, "-json", "run", "vulnerable", "-t", "redis-unauthenticated-access",
		"-expose", "host", "-bind", "127.0.0.1", "-detach", "-ready-timeout", "3s", "-nuclei-templates", t.TempDir())
	if code == ExitOK {
		t.Fatalf("-json run exited 0 although verify failed:\n%s\n%s", out, errOut)
	}
	var handles []struct {
		Ready    bool  `json:"ready"`
		VerifyOK *bool `json:"verify_ok"`
	}
	if err := json.Unmarshal([]byte(out), &handles); err != nil {
		t.Fatalf("JSON not emitted on failure: %v\n%s", err, out)
	}
	if len(handles) != 1 || !handles[0].Ready || handles[0].VerifyOK == nil || *handles[0].VerifyOK {
		t.Fatalf("json handles: %s", out)
	}
}

// The passing counterpart: also proves the host-mode TCP healthcheck and probe
// reach the published host port, not the container port.
func TestRunExitsZeroWhenVerifyPasses(t *testing.T) {
	root := fixtures(t)
	fe := enginetest.New()
	serveOnPublishedPorts(t, fe, "+PONG\r\n")
	code, out, errOut := run(t, fe, "-T", root, "run", "vulnerable", "-t", "redis-unauthenticated-access",
		"-expose", "host", "-bind", "127.0.0.1", "-detach", "-ready-timeout", "3s", "-nuclei-templates", t.TempDir())
	if code != ExitOK || !strings.Contains(out, "verify: ok") || strings.Contains(out, "ready: NO") {
		t.Fatalf("run: %d\n%s\n%s", code, out, errOut)
	}
}

func TestRunExitsNonZeroWhenNotReady(t *testing.T) {
	root := fixtures(t)
	fe := enginetest.New() // nothing listens on the published port
	code, out, errOut := run(t, fe, "-T", root, "run", "vulnerable", "-t", "redis-unauthenticated-access",
		"-expose", "host", "-bind", "127.0.0.1", "-detach", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir())
	if code == ExitOK || !strings.Contains(out, "ready: NO") || !strings.Contains(errOut, "not ready") {
		t.Fatalf("run: %d\n%s\n%s", code, out, errOut)
	}
}
