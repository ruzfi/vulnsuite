package probes

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// proxyServer stands in for Docker's port proxy in host exposure mode with
// nothing listening in the container: it accepts every connection and closes
// it at once without a byte.
func proxyServer(t *testing.T) int {
	t.Helper()
	return serve(t, func(c net.Conn) { c.Close() })
}

// silentServer accepts and waits for the client to speak, as HTTP, redis and
// most databases do; it holds the connection until the client closes it.
func silentServer(t *testing.T) int {
	t.Helper()
	return serve(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 512)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	})
}

func serve(t *testing.T, handle func(net.Conn)) int {
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
			go handle(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// A host port held by a port proxy accepts connections before anything
// listens in the container. That must not make the target ready, a tcp probe
// pass, or a closed: probe fail.
func TestPortProxyWithoutListener(t *testing.T) {
	ctx := context.Background()
	port := proxyServer(t)

	if WaitForPort(ctx, "127.0.0.1", port, 1500*time.Millisecond) {
		t.Error("WaitForPort: ready on a port proxy with nothing behind it")
	}
	if Reachability("127.0.0.1", port, time.Second) != Refused {
		t.Error("Reachability: a port proxy with nothing behind it must count as refused (answering, nothing listens yet)")
	}

	// Host mode: the probe dials a published port (PortMap is set).
	tgt := Target{Host: "127.0.0.1", Port: port, PortMap: map[int]int{}}
	r := Run(ctx, contract.Probe{TCP: &contract.TCPProbe{}}, tgt)
	if r.OK || !strings.Contains(r.Detail, "nothing is listening") {
		t.Errorf("tcp open probe passed against a port proxy with nothing behind it: ok=%v %s", r.OK, r.Detail)
	}
	r = Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Closed: true}}, tgt)
	if !r.OK || !strings.Contains(r.Detail, "closed as expected") {
		t.Errorf("tcp closed probe failed against a port proxy with nothing behind it: ok=%v %s", r.OK, r.Detail)
	}
}

// #151: without a port proxy (internal or macvlan mode, PortMap nil) the
// connection reaches the container itself, so a service that accepts and
// closes at once (tcpwrapped) listens: open passes and closed: fails.
func TestAcceptThenCloseWithoutPortProxy(t *testing.T) {
	ctx := context.Background()
	tgt := Target{Host: "127.0.0.1", Port: proxyServer(t)}
	if r := Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Timeout: 2}}, tgt); !r.OK {
		t.Errorf("tcp open probe failed on an accept-then-close listener: %s", r.Detail)
	}
	if r := Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Closed: true}}, tgt); r.OK {
		t.Errorf("tcp closed probe passed on an accept-then-close listener: %s", r.Detail)
	}
}

// #151: a tcp probe with no send and no banner_matches does not wait out its
// timeout on a server that waits for the client to speak first.
func TestTCPProbeSilentServerNoWait(t *testing.T) {
	port := silentServer(t)
	for name, tgt := range map[string]Target{
		"direct": {Host: "127.0.0.1", Port: port},
		"host":   {Host: "127.0.0.1", Port: port, PortMap: map[int]int{}},
	} {
		start := time.Now()
		r := Run(context.Background(), contract.Probe{TCP: &contract.TCPProbe{Timeout: 5}}, tgt)
		if !r.OK {
			t.Fatalf("%s: %s", name, r.Detail)
		}
		if took := time.Since(start); took > ListenerGrace+time.Second {
			t.Errorf("%s: the probe took %s, want about the listener grace", name, took)
		}
	}
}

// Servers that wait for the client to speak, or greet it, are still detected,
// and promptly.
func TestListenerDetectedPromptly(t *testing.T) {
	ctx := context.Background()
	for name, port := range map[string]int{
		"silent": silentServer(t),
		"banner": lineServer(t, "220 ready\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			if !WaitForPort(ctx, "127.0.0.1", port, 5*time.Second) {
				t.Fatal("WaitForPort: not ready")
			}
			if took := time.Since(start); took > ListenerGrace+time.Second {
				t.Fatalf("WaitForPort took %s", took)
			}
			if Reachability("127.0.0.1", port, time.Second) != Open {
				t.Fatal("Reachability: not open")
			}
			tgt := Target{Host: "127.0.0.1", Port: port}
			if r := Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Timeout: 1}}, tgt); !r.OK {
				t.Fatalf("tcp open: %s", r.Detail)
			}
			if r := Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Closed: true}}, tgt); r.OK {
				t.Fatalf("tcp closed passed on a listening port: %s", r.Detail)
			}
		})
	}
	// A banner read during the listener check is still matched.
	port := lineServer(t, "220 ready\r\n")
	r := Run(ctx, contract.Probe{TCP: &contract.TCPProbe{BannerMatches: `^220 ready`}}, Target{Host: "127.0.0.1", Port: port})
	if !r.OK {
		t.Fatalf("banner lost: %s", r.Detail)
	}
}
