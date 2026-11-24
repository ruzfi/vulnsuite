package probes

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

func TestResultTransportFlag(t *testing.T) {
	host, port, seen := rawServer(t)
	ctx := context.Background()

	// Reached the server, assertion unmet: not a transport failure.
	r := Run(ctx, contract.Probe{HTTP: &contract.HTTPProbe{Path: "/missing", Status: intp(200)}}, Target{Host: host, Port: port, Scheme: "http"})
	<-seen
	if r.OK || r.Transport {
		t.Fatalf("assertion mismatch must not be a transport failure: ok=%v transport=%v %s", r.OK, r.Transport, r.Detail)
	}

	// Nothing listening: a dial failure is a transport failure.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := l.Addr().(*net.TCPAddr).Port
	l.Close()
	r = Run(ctx, contract.Probe{HTTP: &contract.HTTPProbe{Path: "/", Status: intp(200)}}, Target{Host: "127.0.0.1", Port: closedPort, Scheme: "http"})
	if r.OK || !r.Transport {
		t.Fatalf("dial failure must be a transport failure: ok=%v transport=%v %s", r.OK, r.Transport, r.Detail)
	}
}

func TestHTTPProbePortOverrideAndTCPClosed(t *testing.T) {
	// The HTTP server is on its own port; the probe target's primary Port is a
	// different (closed) port, so the probe must honour the per-probe override.
	host, httpPort, seen := rawServer(t)
	ctx := context.Background()

	// find a closed port by opening then closing a listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := l.Addr().(*net.TCPAddr).Port
	l.Close()

	// a plain TCP listener that accepts and waits for the client, for the
	// "open" assertion (one that closes at once looks like a port proxy with
	// nothing behind it; see TestPortProxyWithoutListener)
	openPort := silentServer(t)

	tgt := Target{Host: host, Port: closedPort, Scheme: "http"}

	// HTTP probe with an explicit port reaches the real server despite the
	// primary port being closed.
	r := Run(ctx, contract.Probe{HTTP: &contract.HTTPProbe{Port: httpPort, Path: "/echo-ua", Headers: map[string]string{"User-Agent": "p/1"}, BodyMatches: "^p/1$"}}, tgt)
	<-seen
	if !r.OK {
		t.Fatalf("http port override: %s", r.Detail)
	}

	// TCP closed: the primary (closed) port must assert as closed.
	r = Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Closed: true}}, tgt)
	if !r.OK || !strings.Contains(r.Detail, "closed as expected") {
		t.Fatalf("tcp closed should pass on a refused port: ok=%v %s", r.OK, r.Detail)
	}
	// TCP closed against an OPEN port must fail.
	r = Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Port: openPort, Closed: true}}, tgt)
	if r.OK || !strings.Contains(r.Detail, "open but was expected") {
		t.Fatalf("tcp closed should fail on an open port: ok=%v %s", r.OK, r.Detail)
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

// netServer mimics a line protocol: it greets, then replies per the command
// prefix from the script map.
func netServer(t *testing.T, greet string, reply map[string]string) (string, int) {
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
			go func(c net.Conn) {
				defer c.Close()
				io.WriteString(c, greet)
				buf := make([]byte, 512)
				for {
					c.SetReadDeadline(time.Now().Add(2 * time.Second))
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					line := strings.ToUpper(strings.TrimSpace(string(buf[:n])))
					sent := false
					for prefix, resp := range reply {
						if strings.HasPrefix(line, strings.ToUpper(prefix)) {
							io.WriteString(c, resp)
							sent = true
							break
						}
					}
					if !sent {
						io.WriteString(c, "500 not understood\r\n")
					}
				}
			}(c)
		}
	}()
	a := l.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

func TestNetProbe(t *testing.T) {
	// a mod_copy-style dialogue: the detectable surface is "Copy successful"
	steps := []contract.NetStep{
		{Expect: "^220"},
		{Send: "SITE CPFR /etc/hostname\r\n", Expect: "^350"},
		{Send: "SITE CPTO /tmp/canary\r\n", Expect: "Copy successful"},
	}
	// vulnerable: pre-auth SITE commands succeed
	host, port := netServer(t, "220 ProFTPD 1.3.5 ready\r\n", map[string]string{
		"SITE CPFR": "350 ready for destination\r\n", "SITE CPTO": "250 Copy successful\r\n"})
	r := Run(context.Background(), contract.Probe{Net: &contract.NetProbe{Steps: steps}}, Target{Host: host, Port: port})
	if !r.OK {
		t.Fatalf("vulnerable dialogue should pass: %s", r.Detail)
	}
	// patched: pre-auth denied -> fails at the 350 step, with a trace
	host, port = netServer(t, "220 ProFTPD 1.3.5a ready\r\n", map[string]string{
		"SITE CPFR": "530 Please login with USER and PASS\r\n"})
	r = Run(context.Background(), contract.Probe{Net: &contract.NetProbe{Steps: steps}}, Target{Host: host, Port: port})
	if r.OK || !strings.Contains(r.Detail, "step 2") || !strings.Contains(r.Detail, "530") {
		t.Fatalf("patched dialogue should fail at step 2: ok=%v %s", r.OK, r.Detail)
	}
	// a patched-state probe asserts the patched response explicitly
	patchedVerify := []contract.NetStep{{Expect: "^220"}, {Send: "SITE CPFR /x\r\n", Expect: "530|not understood"}}
	r = Run(context.Background(), contract.Probe{Net: &contract.NetProbe{Steps: patchedVerify}}, Target{Host: host, Port: port})
	if !r.OK {
		t.Fatalf("patched verify should pass: %s", r.Detail)
	}
	// expect_absent
	steps2 := []contract.NetStep{{Expect: "^220"}, {Send: "SITE CPFR /x\r\n", ExpectAbsent: "Copy successful"}}
	r = Run(context.Background(), contract.Probe{Net: &contract.NetProbe{Steps: steps2}}, Target{Host: host, Port: port})
	if !r.OK {
		t.Fatalf("expect_absent should pass on patched: %s", r.Detail)
	}
}

// A regex that does not compile must fail its probe. matchDotAll treats it as
// "no match", so an *_absent check used to pass, and a patched state verified
// OK against a target that was still vulnerable.
func TestInvalidRegexFailsProbe(t *testing.T) {
	host, port, _ := rawServer(t)
	tgt := Target{Host: host, Port: port, Container: "c",
		Exec: func(ctx context.Context, container, command string, timeout time.Duration) (int, string, error) {
			return 0, "uid=0(root)", nil
		}}
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
			io.WriteString(c, "220 banner\r\n")
			c.Close()
		}
	}()
	tcpPort := l.Addr().(*net.TCPAddr).Port
	bad := "root:x:0:0(" // unbalanced paren
	cases := map[string]contract.Probe{
		"http body_absent":   {HTTP: &contract.HTTPProbe{Path: "/etc/passwd", BodyAbsent: bad}},
		"http body_matches":  {HTTP: &contract.HTTPProbe{Path: "/etc/passwd", BodyMatches: bad}},
		"http header":        {HTTP: &contract.HTTPProbe{Path: "/etc/passwd", HeaderMatches: map[string]string{"X-Served": "("}}},
		"exec stdout":        {Exec: &contract.ExecProbe{Run: "id", StdoutMatches: "("}},
		"tcp banner":         {TCP: &contract.TCPProbe{Port: tcpPort, BannerMatches: "("}},
		"net expect_absent":  {Net: &contract.NetProbe{Port: tcpPort, Steps: []contract.NetStep{{ExpectAbsent: bad}}}},
		"net expect (later)": {Net: &contract.NetProbe{Port: tcpPort, Steps: []contract.NetStep{{Expect: "220"}, {Expect: "["}}}},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			tt := tgt
			if p.TCP != nil || p.Net != nil {
				tt.Port = tcpPort
			}
			r := Run(context.Background(), p, tt)
			if r.OK {
				t.Fatalf("probe with an invalid regex passed: %s", r.Detail)
			}
			if !strings.Contains(r.Detail, "invalid regex") || r.Transport {
				t.Fatalf("want a non-transport invalid regex failure, got transport=%v %q", r.Transport, r.Detail)
			}
		})
	}
	// Valid patterns still pass.
	if r := Run(context.Background(), contract.Probe{HTTP: &contract.HTTPProbe{Path: "/etc/passwd", BodyMatches: `root:x:0:0`, BodyAbsent: `nobody\(`}}, tgt); !r.OK {
		t.Fatalf("valid patterns: %s", r.Detail)
	}
}

// Without an executor a sequence probe fails with a clear detail and never
// touches the target; with one, Run hands it the sequence and fills in the
// kind and elapsed time.
func TestRunSequence(t *testing.T) {
	called := false
	tgt := Target{Container: "c", Exec: func(context.Context, string, string, time.Duration) (int, string, error) {
		called = true
		return 0, "", nil
	}}
	p := contract.Probe{Sequence: &contract.SequenceProbe{Steps: []contract.SequenceStep{
		{Exec: &contract.SequenceExec{ExecProbe: contract.ExecProbe{Run: "true", ExpectExit: new(int)}}},
	}}}
	r := Run(context.Background(), p, tgt)
	if r.OK || r.Kind != "sequence" || r.Detail != SequenceUnsupported || r.Transport || called {
		t.Fatalf("result = %+v, exec called %v", r, called)
	}
	ok, rs := RunAll(context.Background(), []contract.Probe{p}, tgt)
	if ok || FormatResults(rs) != "FAIL "+SequenceUnsupported {
		t.Fatalf("RunAll = %v %q", ok, FormatResults(rs))
	}

	var got *contract.SequenceProbe
	tgt.Sequence = func(_ context.Context, s *contract.SequenceProbe) Result {
		got = s
		time.Sleep(time.Millisecond)
		return Result{OK: true, Detail: "sequence: 1/1 passed, 0 failed: #1 pass: ok",
			Attempts: []SequenceAttempt{{Attempt: 1, Outcome: OutcomePass, Detail: "ok"}}}
	}
	r = Run(context.Background(), p, tgt)
	if got != p.Sequence || !r.OK || r.Kind != "sequence" || r.Elapsed < time.Millisecond || len(r.Attempts) != 1 {
		t.Fatalf("result = %+v", r)
	}
}

// A sequence step's bad regexp is reported like any other probe's.
func TestRunSequenceBadRegex(t *testing.T) {
	bad := "("
	for _, st := range []contract.SequenceStep{
		{ExpectLog: &bad},
		{ExpectSanitizer: &contract.ExpectSanitizer{Kind: "heap-use-after-free", Frame: bad}},
		{Exec: &contract.SequenceExec{ExecProbe: contract.ExecProbe{Run: "x", StdoutMatches: bad}}},
		{Net: &contract.NetProbe{Steps: []contract.NetStep{{Expect: bad}}}},
	} {
		r := Run(context.Background(), contract.Probe{Sequence: &contract.SequenceProbe{Steps: []contract.SequenceStep{st}}}, Target{})
		if r.OK || !strings.Contains(r.Detail, "invalid regex in sequence probe steps[0]") {
			t.Errorf("%s: %+v", st.Kind(), r)
		}
	}
}

// #146: closed: passes only on a refused connection; a dial that times out,
// finds no route or cannot resolve the host cannot tell, so it is a transport
// failure (verify then says "could not verify from here").
func TestTCPClosedOnlyOnRefused(t *testing.T) {
	ctx := context.Background()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := l.Addr().(*net.TCPAddr).Port
	l.Close()
	r := Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Closed: true}}, Target{Host: "127.0.0.1", Port: refused})
	if !r.OK || r.Transport {
		t.Fatalf("refused port: ok=%v transport=%v %s", r.OK, r.Transport, r.Detail)
	}
	for name, host := range map[string]string{
		"unresolvable": "no-such-host.invalid",
		"blackholed":   "192.0.2.1", // TEST-NET-1: times out or has no route
	} {
		t.Run(name, func(t *testing.T) {
			r := Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Closed: true, Timeout: 0.5}}, Target{Host: host, Port: 6379})
			if r.OK || !r.Transport || !strings.Contains(r.Detail, "cannot tell whether it is closed") {
				t.Fatalf("ok=%v transport=%v %s", r.OK, r.Transport, r.Detail)
			}
		})
	}
	// A cancelled probe is not a pass either.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if r := Run(cctx, contract.Probe{TCP: &contract.TCPProbe{Closed: true}}, Target{Host: "127.0.0.1", Port: refused}); r.OK {
		t.Fatalf("cancelled closed: probe passed: %s", r.Detail)
	}
}

// #146: a failed exec probe (or sequence exec step) quotes the command's
// output, truncated; a passing one does not.
func TestExecFailureDetailIncludesOutput(t *testing.T) {
	ctx := context.Background()
	execWith := func(code int, out string, err error) Target {
		return Target{Container: "c", Exec: func(context.Context, string, string, time.Duration) (int, string, error) { return code, out, err }}
	}
	r := Run(ctx, contract.Probe{Exec: &contract.ExecProbe{Run: "cat /etc/shadow", StdoutMatches: "root:"}}, execWith(1, "cat: /etc/shadow: Permission denied\n", nil))
	if r.OK || !strings.Contains(r.Detail, `output: "cat: /etc/shadow: Permission denied"`) {
		t.Fatalf("ok=%v %s", r.OK, r.Detail)
	}
	r = Run(ctx, contract.Probe{Exec: &contract.ExecProbe{Run: "hang"}}, execWith(-1, "partial", errors.New("exec timed out: context deadline exceeded")))
	if r.OK || !strings.Contains(r.Detail, "timed out") || !strings.Contains(r.Detail, `output: "partial"`) {
		t.Fatalf("ok=%v %s", r.OK, r.Detail)
	}
	long := strings.Repeat("é", 600) // 1200 bytes, the cut must not split a rune
	r = Run(ctx, contract.Probe{Exec: &contract.ExecProbe{Run: "x"}}, execWith(2, long, nil))
	if r.OK || !strings.Contains(r.Detail, "output (first 512 of 1200 bytes)") || len(r.Detail) > 1500 || !utf8.ValidString(r.Detail) {
		t.Fatalf("ok=%v len=%d %s", r.OK, len(r.Detail), r.Detail)
	}
	r = Run(ctx, contract.Probe{Exec: &contract.ExecProbe{Run: "x"}}, execWith(1, "  \n", nil))
	if r.OK || strings.Contains(r.Detail, "output") {
		t.Fatalf("empty output quoted: %s", r.Detail)
	}
	r = Run(ctx, contract.Probe{Exec: &contract.ExecProbe{Run: "x", StdoutMatches: "ok"}}, execWith(0, "ok", nil))
	if !r.OK || strings.Contains(r.Detail, "output") {
		t.Fatalf("pass: ok=%v %s", r.OK, r.Detail)
	}
}
