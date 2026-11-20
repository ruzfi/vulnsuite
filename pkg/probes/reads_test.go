package probes

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// segmentedFTP greets in two TCP segments, like a multi-line FTP banner, then
// answers USER with a reply of its own.
func segmentedFTP(t *testing.T) int {
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
				_, _ = c.Write([]byte("220-Welcome\r\n"))
				time.Sleep(100 * time.Millisecond)
				_, _ = c.Write([]byte("220 ready\r\n"))
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				if strings.HasPrefix(line, "USER") {
					_, _ = c.Write([]byte("331 password please\r\n"))
				}
				time.Sleep(time.Second) // hold the connection open
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// A reply sent in several segments is judged whole, and its tail does not
// leak into the next step's read.
func TestReadsSpanSegments(t *testing.T) {
	ctx := context.Background()
	port := segmentedFTP(t)
	tgt := Target{Host: "127.0.0.1", Port: port}

	r := Run(ctx, contract.Probe{Net: &contract.NetProbe{Steps: []contract.NetStep{
		{Expect: "220 ready"},
		{Send: "USER anonymous\r\n", Expect: "^331"},
	}}}, tgt)
	if !r.OK {
		t.Errorf("net: %s", r.Detail)
	}
	r = Run(ctx, contract.Probe{TCP: &contract.TCPProbe{BannerMatches: "220 ready"}}, tgt)
	if !r.OK {
		t.Errorf("tcp banner: %s", r.Detail)
	}
	// Without expect, the whole multi-segment banner is read, so an
	// expect_absent sees all of it.
	r = Run(ctx, contract.Probe{Net: &contract.NetProbe{Steps: []contract.NetStep{{ExpectAbsent: "ready"}}}}, tgt)
	if r.OK {
		t.Errorf("expect_absent passed on a banner whose second segment matches: %s", r.Detail)
	}
}

// A chunk extension may have whitespace before its ';' (RFC 9112 7.1.1).
func TestDechunkExtensionWhitespace(t *testing.T) {
	for in, want := range map[string]string{
		"5 ;x=y\r\nhello\r\n0\r\n\r\n":                    "hello",
		"5\t; x=y\r\nhello\r\n6;a\r\n world\r\n0\r\n\r\n": "hello world",
		"5\r\nhello\r\n0\r\n\r\n":                         "hello",
	} {
		if got := dechunk(in); got != want {
			t.Errorf("dechunk(%q) = %q, want %q", in, got, want)
		}
	}
	resp, err := parseHTTP([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5 ;x=y\r\nhello\r\n0\r\n\r\n"))
	if err != nil || resp.Body != "hello" {
		t.Fatalf("parseHTTP body %q, %v", resp.Body, err)
	}
}

// Cancelling the context stops a probe that is waiting on a read at once, not
// after the probe's own (template-chosen) timeout.
func TestProbeReadsHonourCancel(t *testing.T) {
	host, port := stallServer(t)
	tgt := Target{Host: host, Port: port}
	for name, run := range map[string]func(ctx context.Context) error{
		"http": func(ctx context.Context) error {
			_, err := RawHTTP(ctx, host, port, "GET", "/", nil, "", 30*time.Second, false)
			return err
		},
		"tcp": func(ctx context.Context) error {
			r := Run(ctx, contract.Probe{TCP: &contract.TCPProbe{Timeout: 30, BannerMatches: "x"}}, tgt)
			if r.OK {
				t.Error("tcp passed")
			}
			return nil
		},
		"net": func(ctx context.Context) error {
			r := Run(ctx, contract.Probe{Net: &contract.NetProbe{Timeout: 30, Steps: []contract.NetStep{{Expect: "x"}}}}, tgt)
			if r.OK {
				t.Error("net passed")
			}
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(200*time.Millisecond, cancel)
			start := time.Now()
			_ = run(ctx)
			if el := time.Since(start); el > 3*time.Second {
				t.Fatalf("returned %s after cancel; want promptly", el)
			}
		})
	}
}
