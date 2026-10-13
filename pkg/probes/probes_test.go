package probes

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// rawServer answers HTTP without normalising the request line, so the test
// can assert the probe sent the traversal payload verbatim.
func rawServer(t *testing.T) (host string, port int, seen chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	seen = make(chan string, 16)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				line, _ := r.ReadString('\n')
				seen <- strings.TrimSpace(line)
				hdrs := map[string]string{}
				for {
					h, err := r.ReadString('\n')
					if err != nil || strings.TrimSpace(h) == "" {
						break
					}
					k, v, _ := strings.Cut(h, ":")
					hdrs[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
				}
				path := strings.Fields(line)[1]
				switch {
				case strings.Contains(path, "/etc/passwd"):
					body := "root:x:0:0:root:/root:/bin/sh\n"
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Served: yes\r\n\r\n%s", len(body), body)
				case path == "/chunked":
					fmt.Fprint(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
				case path == "/redirect":
					fmt.Fprint(c, "HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n")
				case path == "/echo-ua":
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(hdrs["user-agent"]), hdrs["user-agent"])
				default:
					fmt.Fprint(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
				}
			}(conn)
		}
	}()
	addr := l.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, seen
}

func intp(i int) *int { return &i }

func TestHTTPProbeVerbatimAndAssertions(t *testing.T) {
	host, port, seen := rawServer(t)
	tgt := Target{Host: host, Port: port, Scheme: "http"}
	ctx := context.Background()

	raw := "/icons/.%2e/%2e%2e/%2e%2e/etc/passwd"
	r := Run(ctx, contract.Probe{HTTP: &contract.HTTPProbe{RawPath: raw, Status: intp(200), BodyMatches: "root:.*:0:0:", HeaderMatches: map[string]string{"X-Served": "^yes$"}}}, tgt)
	if !r.OK {
		t.Fatalf("expected ok: %s", r.Detail)
	}
	if line := <-seen; line != "GET "+raw+" HTTP/1.1" {
		t.Fatalf("payload was altered on the wire: %q", line)
	}
	// patched-style assertion against the same (still vulnerable) server fails loudly
	r = Run(ctx, contract.Probe{HTTP: &contract.HTTPProbe{RawPath: raw, StatusIn: []int{403, 404}, BodyAbsent: "root:"}}, tgt)
	<-seen
	if r.OK || !strings.Contains(r.Detail, "status 200 not in") || !strings.Contains(r.Detail, "unexpectedly") {
		t.Fatalf("expected failure detail, got ok=%v %s", r.OK, r.Detail)
	}
	// chunked bodies are decoded
	r = Run(ctx, contract.Probe{HTTP: &contract.HTTPProbe{Path: "/chunked", BodyMatches: "^hello world$"}}, tgt)
	<-seen
	if !r.OK {
		t.Fatalf("chunked: %s", r.Detail)
	}
	// header assertions: open redirect
	r = Run(ctx, contract.Probe{HTTP: &contract.HTTPProbe{Path: "/redirect", Status: intp(302), HeaderMatches: map[string]string{"Location": `^https?://evil`}, HeaderAbsent: []string{"Set-Cookie"}}}, tgt)
	<-seen
	if !r.OK {
		t.Fatalf("redirect: %s", r.Detail)
	}
	r = Run(ctx, contract.Probe{HTTP: &contract.HTTPProbe{Path: "/redirect", HeaderAbsent: []string{"Location"}}}, tgt)
	<-seen
	if r.OK {
		t.Fatal("header_absent should fail when the header is present")
	}
	// custom headers override defaults
	r = Run(ctx, contract.Probe{HTTP: &contract.HTTPProbe{Path: "/echo-ua", Headers: map[string]string{"User-Agent": "custom/1"}, BodyMatches: "^custom/1$"}}, tgt)
	<-seen
	if !r.OK {
		t.Fatalf("custom header: %s", r.Detail)
	}
}

func TestTCPProbeAndReachability(t *testing.T) {
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
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				if strings.HasPrefix(string(buf[:n]), "PING") {
					fmt.Fprint(c, "+PONG\r\n")
				} else {
					fmt.Fprint(c, "-NOAUTH Authentication required.\r\n")
				}
			}(c)
		}
	}()
	addr := l.Addr().(*net.TCPAddr)
	tgt := Target{Host: "127.0.0.1", Port: addr.Port}
	r := Run(context.Background(), contract.Probe{TCP: &contract.TCPProbe{Port: addr.Port, Send: "PING\r\n", BannerMatches: `\+PONG`}}, tgt)
	if !r.OK {
		t.Fatalf("tcp: %s", r.Detail)
	}
	r = Run(context.Background(), contract.Probe{TCP: &contract.TCPProbe{Port: addr.Port, Send: "GET\r\n", BannerMatches: `\+PONG`}}, tgt)
	if r.OK {
		t.Fatal("banner mismatch must fail")
	}
	if Reachability("127.0.0.1", addr.Port, time.Second) != Open {
		t.Fatal("expected open")
	}
	l.Close()
	if Reachability("127.0.0.1", addr.Port, time.Second) != Refused {
		t.Fatal("expected refused after close")
	}
	if Reachability("10.255.255.1", 9, 300*time.Millisecond) != Unreachable {
		t.Fatal("expected unreachable")
	}
}

func TestExecProbe(t *testing.T) {
	exec := func(ctx context.Context, container, command string, timeout time.Duration) (int, string, error) {
		if command == "id" {
			return 0, "uid=0(root) gid=0(root)", nil
		}
		return 1, "", nil
	}
	tgt := Target{Container: "c", Exec: exec}
	r := Run(context.Background(), contract.Probe{Exec: &contract.ExecProbe{Run: "id", StdoutMatches: "uid=0"}}, tgt)
	if !r.OK {
		t.Fatal(r.Detail)
	}
	r = Run(context.Background(), contract.Probe{Exec: &contract.ExecProbe{Run: "false", ExpectExit: intp(1)}}, tgt)
	if !r.OK {
		t.Fatal(r.Detail)
	}
	r = Run(context.Background(), contract.Probe{Exec: &contract.ExecProbe{Run: "id"}}, Target{})
	if r.OK {
		t.Fatal("exec without a backend must fail")
	}
	ok, rs := RunAll(context.Background(), []contract.Probe{{Exec: &contract.ExecProbe{Run: "id"}}, {Exec: &contract.ExecProbe{Run: "false"}}}, tgt)
	if ok || len(rs) != 2 || !strings.Contains(FormatResults(rs), "FAIL") {
		t.Fatalf("RunAll: %v %s", ok, FormatResults(rs))
	}
}

func TestParseHTTPTolerant(t *testing.T) {
	resp, err := parseHTTP([]byte("HTTP/1.0 200 OK\nContent-Type: text/plain\n\nhi"))
	if err != nil || resp.Status != 200 || resp.Body != "hi" || resp.Headers["content-type"] != "text/plain" {
		t.Fatalf("%+v %v", resp, err)
	}
	if _, err := parseHTTP([]byte("not http")); err == nil {
		t.Fatal("expected error")
	}
}
