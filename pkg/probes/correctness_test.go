package probes

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// stallServer accepts connections and never writes, holding them open: a TLS
// client handshaking against it waits forever unless a deadline cuts it off.
func stallServer(t *testing.T) (string, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	done := make(chan struct{})
	t.Cleanup(func() {
		l.Close()
		<-done
		for _, c := range conns {
			c.Close()
		}
	})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	a := l.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// A stalled TLS peer must be cut off by the probe timeout, not the (possibly
// deadline-less) parent context.
func TestTLSHandshakeHonoursProbeTimeout(t *testing.T) {
	host, port := stallServer(t)
	ctx := context.Background() // no deadline, like the CLI

	start := time.Now()
	r := Run(ctx, contract.Probe{HTTP: &contract.HTTPProbe{Path: "/", Timeout: 0.3}}, Target{Host: host, Port: port, Scheme: "https"})
	if r.OK {
		t.Fatal("stalled https probe passed")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("https probe took %v, want ~0.3s", el)
	}

	start = time.Now()
	r = Run(ctx, contract.Probe{Net: &contract.NetProbe{TLS: true, Timeout: 0.3, Steps: []contract.NetStep{{Send: "x"}}}}, Target{Host: host, Port: port})
	if r.OK {
		t.Fatal("stalled tls net probe passed")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("tls net probe took %v, want ~0.3s", el)
	}

	start = time.Now()
	if WaitForHTTP(ctx, host, port, "https", "/", 0, 500*time.Millisecond) {
		t.Fatal("WaitForHTTP against a stalled peer reported ready")
	}
	if el := time.Since(start); el > 8*time.Second {
		t.Fatalf("WaitForHTTP took %v; the handshake was not bounded", el)
	}
}

func TestRepeatedHeadersAreJoined(t *testing.T) {
	resp, err := parseHTTP([]byte("HTTP/1.1 200 OK\r\nSet-Cookie: sess=1; HttpOnly\r\nSet-Cookie: sess=2\r\nX-One: a\r\n\r\nbody"))
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Headers["set-cookie"]; got != "sess=1; HttpOnly, sess=2" {
		t.Fatalf("set-cookie = %q", got)
	}
	if resp.Headers["x-one"] != "a" {
		t.Fatalf("x-one = %q", resp.Headers["x-one"])
	}
}

// header_matches on the first of two Set-Cookie headers must see it.
func TestHeaderMatchesSeesEveryRepeatedHeader(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nSet-Cookie: sess=1; HttpOnly\r\nSet-Cookie: theme=dark\r\nContent-Length: 0\r\n\r\n"))
			}(c)
		}
	}()
	a := l.Addr().(*net.TCPAddr)
	tgt := Target{Host: a.IP.String(), Port: a.Port, Scheme: "http"}
	r := Run(context.Background(), contract.Probe{HTTP: &contract.HTTPProbe{Path: "/", HeaderMatches: map[string]string{"Set-Cookie": `sess=1; HttpOnly`}}}, tgt)
	if !r.OK {
		t.Fatalf("header_matches missed the first Set-Cookie: %s", r.Detail)
	}
}

// In host exposure mode a probe's port: is a container port; it must be dialled
// on its published host port, and an unpublished port must not pass a closed:
// assertion by default.
func TestProbePortMapTranslatesContainerPorts(t *testing.T) {
	host, httpHostPort, seen := rawServer(t)
	open, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	go func() {
		for {
			c, err := open.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("+PONG\r\n"))
			c.Close()
		}
	}()
	tcpHostPort := open.Addr().(*net.TCPAddr).Port
	ctx := context.Background()
	// container 8080 -> httpHostPort, container 6379 -> tcpHostPort; 9999 unpublished.
	tgt := Target{Host: host, Port: httpHostPort, Scheme: "http", PortMap: map[int]int{8080: httpHostPort, 6379: tcpHostPort}}

	r := Run(ctx, contract.Probe{HTTP: &contract.HTTPProbe{Port: 8080, Path: "/etc/passwd", BodyMatches: "root:"}}, tgt)
	<-seen
	if !r.OK {
		t.Fatalf("http port 8080 not translated: %s", r.Detail)
	}
	r = Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Port: 6379, BannerMatches: "PONG"}}, tgt)
	if !r.OK {
		t.Fatalf("tcp port 6379 not translated: %s", r.Detail)
	}
	r = Run(ctx, contract.Probe{Net: &contract.NetProbe{Port: 6379, Steps: []contract.NetStep{{Expect: "PONG"}}}}, tgt)
	if !r.OK {
		t.Fatalf("net port 6379 not translated: %s", r.Detail)
	}
	// The container port itself is closed on the host; it must not be what is dialled.
	r = Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Port: 6379, Closed: true}}, tgt)
	if r.OK {
		t.Fatalf("closed: on a published, listening port passed: %s", r.Detail)
	}
	r = Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Port: 9999, Closed: true}}, tgt)
	if r.OK || !strings.Contains(r.Detail, "not published") {
		t.Fatalf("closed: on an unpublished port must not pass: ok=%v %s", r.OK, r.Detail)
	}
	if !r.Skipped || r.Transport {
		t.Errorf("#151: closed: on an unpublished port must be skipped, not failed: %+v", r)
	}
	r = Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Port: 9999}}, tgt)
	if r.OK || !strings.Contains(r.Detail, "not published") {
		t.Fatalf("tcp on an unpublished port: ok=%v %s", r.OK, r.Detail)
	}
	// #151: every network kind on an unpublished port is skipped.
	for _, p := range []contract.Probe{
		{TCP: &contract.TCPProbe{Port: 9999}},
		{HTTP: &contract.HTTPProbe{Port: 9999, Path: "/"}},
		{Net: &contract.NetProbe{Port: 9999, Steps: []contract.NetStep{{Send: "x"}}}},
	} {
		if r := Run(ctx, p, tgt); r.OK || !r.Skipped {
			t.Errorf("%s on an unpublished port: want skipped, got %+v", p.Kind(), r)
		}
	}
	// A published port that fails is never skipped.
	if r := Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Port: 6379, Closed: true}}, tgt); r.Skipped {
		t.Errorf("a failed probe on a published port was marked skipped: %+v", r)
	}
	if got := FormatResults([]Result{{Skipped: true, Detail: "d"}}); got != "skip d" {
		t.Errorf("FormatResults(skipped) = %q", got)
	}
}
