package runner

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

// silentListener accepts connections and holds them without a byte, as a
// server that waits for the client to speak first does.
func silentListener(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 512)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// hostModeHandle is a ready host-mode target whose primary container port
// 6379 is published on hostPort and no other port is.
func hostModeHandle(hostPort int) *Handle {
	return &Handle{
		ID: "redis-unauthenticated-access", State: "vulnerable", Container: "vulnsuite-test",
		Exposure: Exposure{Mode: ModeHost, Bind: "127.0.0.1"}, Ready: true,
		EndpointHost: "127.0.0.1", EndpointPort: hostPort,
		PublishedPorts: []PublishedPort{{ContainerPort: 6379, HostIP: "127.0.0.1", HostPort: hostPort}},
	}
}

// #151 item 2: in host mode a probe (or a sequence's network step) on a
// container port that is not published cannot run from here. It is skipped,
// not failed: verify is partial (VerifyOK nil) unless another probe fails.
func TestHostModeUnpublishedPortProbeSkipped(t *testing.T) {
	port := silentListener(t)
	r := New(enginetest.New())
	c := load(t, "redis-unauthenticated-access")
	st := &contract.State{Verify: []contract.Probe{
		{TCP: &contract.TCPProbe{Timeout: 2}},               // the published primary: passes
		{TCP: &contract.TCPProbe{Port: 6380, Closed: true}}, // undeclared, unpublished
		{HTTP: &contract.HTTPProbe{Port: 8080, Path: "/"}},  // unpublished
		{Sequence: &contract.SequenceProbe{Steps: []contract.SequenceStep{
			{TCP: &contract.TCPProbe{Port: 6380, Send: "PING\r\n"}},
		}}},
	}}
	h := hostModeHandle(port)
	r.verify(context.Background(), c, st, h)
	if h.VerifyOK != nil {
		t.Fatalf("verify = %v, want not verified (nil): %s", *h.VerifyOK, h.VerifyDetail)
	}
	if !strings.Contains(h.VerifyDetail, "skip 3 probe(s)") || !strings.Contains(h.VerifyDetail, "publish: true") {
		t.Errorf("detail should count the skipped probes and name the fix: %q", h.VerifyDetail)
	}
	if len(h.Probes) != 4 || !h.Probes[0].OK || !h.Probes[1].Skipped || !h.Probes[2].Skipped || !h.Probes[3].Skipped {
		t.Errorf("probe results: %+v", h.Probes)
	}
	if h.Problem() != "" {
		t.Errorf("a skipped probe is not a problem: %q", h.Problem())
	}

	// A probe that runs and fails still fails verify.
	st.Verify = append(st.Verify, contract.Probe{TCP: &contract.TCPProbe{Closed: true}})
	h = hostModeHandle(port)
	r.verify(context.Background(), c, st, h)
	if h.VerifyOK == nil || *h.VerifyOK {
		t.Fatalf("a failed probe next to skipped ones must fail verify: %v %s", h.VerifyOK, h.VerifyDetail)
	}
}

// #151 item 4: in internal mode with a remote daemon the container IP is on
// that machine's bridge; this machine must not dial it (a local container can
// hold the same IP). Readiness runs inside the target and network probes are
// skipped.
func TestInternalRemoteDaemonDoesNotDialContainerIP(t *testing.T) {
	fe := enginetest.New()
	fe.HostAddr = "tcp://10.0.0.5:2375"
	r := New(fe)
	dialled := false
	r.Reach = func(string, int, time.Duration) probes.Reach { dialled = true; return probes.Open }
	c := load(t, "redis-unauthenticated-access")
	h, err := r.Run(context.Background(), c, "vulnerable", DefaultExposure(), Options{Verify: true, ReadyTimeout: 5 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !h.DaemonRemote || h.IP == "" {
		t.Fatalf("want a remote daemon and a container IP: remote=%v ip=%q", h.DaemonRemote, h.IP)
	}
	if dialled {
		t.Error("readiness dialled the remote daemon's container IP from here")
	}
	if host, _ := r.probeAddress(h, c); host != "" {
		t.Errorf("probeAddress = %q, want \"\" for a remote daemon in internal mode", host)
	}
	if !h.Ready {
		t.Fatalf("not ready: %s", h.ReadyDetail)
	}
	if h.VerifyOK != nil || !strings.Contains(h.VerifyDetail, "could not verify") {
		t.Fatalf("verify should be skipped with a reason: %v %q", h.VerifyOK, h.VerifyDetail)
	}
	sawInside := false
	for _, cmd := range fe.Execs {
		sawInside = sawInside || isHealthcheck(cmd)
	}
	if !sawInside {
		t.Error("the healthcheck did not run inside the target")
	}
}

// #151: the inside healthcheck's exec timeout is clamped to the time left, so
// a short healthcheck timeout is not overrun by the full exec timeout.
func TestInsideHealthcheckExecTimeoutClamped(t *testing.T) {
	fe := enginetest.New()
	fe.ExecFn = func(string, string) (int, string, error) { return insideNotReady, "", nil }
	r := unreachableRunner(fe)
	c := load(t, "redis-unauthenticated-access")
	const ready = 1500 * time.Millisecond
	h, err := r.Run(context.Background(), c, "vulnerable", DefaultExposure(), Options{ReadyTimeout: ready, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.Ready {
		t.Fatal("ready on a check that never passes")
	}
	if len(fe.ExecTimeouts) == 0 {
		t.Fatal("no inside check ran")
	}
	for _, d := range fe.ExecTimeouts {
		if d > ready || d < insideMinExecTimeout {
			t.Errorf("exec timeout %s outside [%s, %s]", d, insideMinExecTimeout, ready)
		}
	}
	for left, want := range map[time.Duration]time.Duration{
		time.Minute:       insideExecTimeout,
		3 * time.Second:   3 * time.Second,
		0:                 insideMinExecTimeout,
		-time.Second:      insideMinExecTimeout,
		insideExecTimeout: insideExecTimeout,
	} {
		if got := insideExecBudget(left); got != want {
			t.Errorf("insideExecBudget(%s) = %s, want %s", left, got, want)
		}
	}
}
