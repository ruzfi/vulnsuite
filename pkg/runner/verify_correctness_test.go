package runner

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

// serveRedisOnPublishedPorts makes the fake "start" a container by listening on
// each of its published host ports and answering like an unauthenticated Redis.
func serveRedisOnPublishedPorts(t *testing.T, fe *enginetest.Fake) {
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
						buf := make([]byte, 64)
						if n, _ := c.Read(buf); n > 0 {
							_, _ = c.Write([]byte("+PONG\r\n"))
						}
					}(c)
				}
			}()
		}
		return nil
	}
}

// In host mode the TCP healthcheck (tcp.port: 6379) and the probe's port: 6379
// are container ports and must be dialled on the published host port.
func TestHostModeTCPHealthcheckAndProbeUsePublishedPort(t *testing.T) {
	fe := enginetest.New()
	serveRedisOnPublishedPorts(t, fe)
	r := New(fe)
	c := load(t, "redis-unauthenticated-access")
	h, err := r.Run(context.Background(), c, "vulnerable", Exposure{Mode: ModeHost, Bind: "127.0.0.1"},
		Options{Verify: true, ReadyTimeout: 3 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.EndpointPort == 6379 {
		t.Skip("host port happened to equal the container port")
	}
	if !h.Ready {
		t.Fatal("tcp healthcheck dialled the container port instead of the published host port")
	}
	if h.VerifyOK == nil || !*h.VerifyOK {
		t.Fatalf("verify should pass on the published port: %v %s", h.VerifyOK, h.VerifyDetail)
	}
	if p := h.Problem(); p != "" {
		t.Fatalf("problem: %s", p)
	}
}

func TestSeedFailureIsRecordedAndFailsVerify(t *testing.T) {
	fe := enginetest.New()
	serveRedisOnPublishedPorts(t, fe)
	fe.ExecFn = func(_, command string) (int, string, error) {
		if command == "exit 3" {
			return 3, "seed went wrong", nil
		}
		return 0, "", nil
	}
	r := New(fe)
	c := load(t, "redis-unauthenticated-access")
	c.States["vulnerable"].Seed = []contract.SeedStep{{Run: "exit 3"}, {Run: "echo after"}}
	h, err := r.Run(context.Background(), c, "vulnerable", Exposure{Mode: ModeHost, Bind: "127.0.0.1"},
		Options{Verify: true, ReadyTimeout: 3 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !h.Ready {
		t.Fatal("not ready")
	}
	if len(h.Seeds) != 2 || h.Seeds[0].OK || h.Seeds[0].ExitCode != 3 || !strings.Contains(h.Seeds[0].Output, "seed went wrong") {
		t.Fatalf("seed 0: %+v", h.Seeds)
	}
	if !h.Seeds[1].Skipped || h.Seeds[1].OK {
		t.Fatalf("a step after a failed one must be skipped: %+v", h.Seeds[1])
	}
	if len(fe.Execs) != 1 {
		t.Fatalf("execs: %v", fe.Execs)
	}
	// The probes pass, but the seeded state is not guaranteed.
	if h.VerifyOK == nil || *h.VerifyOK {
		t.Fatalf("verify must fail when a seed failed: %v", h.VerifyOK)
	}
	if !strings.Contains(h.VerifyDetail, `seed "exit 3"`) {
		t.Fatalf("verify detail should name the seed: %q", h.VerifyDetail)
	}
	if !strings.Contains(h.Problem(), "seed failed") {
		t.Fatalf("problem: %q", h.Problem())
	}
}

// With verify unavailable (internal mode, unroutable), a failed seed is still
// reported in the detail and as a problem.
func TestSeedFailureReportedWhenVerifyCannotRun(t *testing.T) {
	fe := enginetest.New()
	fe.ExecFn = func(string, string) (int, string, error) { return 1, "", nil }
	r := New(fe)
	r.Reach = func(string, int, time.Duration) probes.Reach { return probes.Unreachable }
	c := load(t, "redis-unauthenticated-access")
	c.States["vulnerable"].Seed = []contract.SeedStep{{Run: "false"}}
	h, err := r.Run(context.Background(), c, "vulnerable", DefaultExposure(), Options{Verify: true, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.VerifyOK != nil {
		t.Fatalf("verify should be unverifiable here: %v", *h.VerifyOK)
	}
	if !strings.Contains(h.VerifyDetail, `seed "false"`) || !strings.Contains(h.Problem(), "seed failed") {
		t.Fatalf("detail=%q problem=%q", h.VerifyDetail, h.Problem())
	}
}

func TestSeedsSkippedWhenNotReady(t *testing.T) {
	fe := enginetest.New() // nothing listens on the published port
	r := New(fe)
	r.Reach = func(string, int, time.Duration) probes.Reach { return probes.Refused }
	c := load(t, "redis-unauthenticated-access")
	c.States["vulnerable"].Seed = []contract.SeedStep{{Run: "seed-cmd"}}
	h, err := r.Run(context.Background(), c, "vulnerable", Exposure{Mode: ModeHost, Bind: "127.0.0.1"},
		Options{ReadyTimeout: time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.Ready {
		t.Fatal("should not be ready")
	}
	if len(fe.Execs) != 0 {
		t.Fatalf("seeds ran on a target that is not ready: %v", fe.Execs)
	}
	if len(h.Seeds) != 1 || !h.Seeds[0].Skipped || h.Seeds[0].OK {
		t.Fatalf("seeds: %+v", h.Seeds)
	}
	if p := h.Problem(); p != "not ready" {
		t.Fatalf("problem: %q", p)
	}
}
