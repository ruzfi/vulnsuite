package probes

import (
	"context"
	"net"
	"testing"
	"time"
)

// keepAliveServer answers every connection with resp and then holds it open
// (ignoring Connection: close), like a keep-alive server would.
func keepAliveServer(t *testing.T, resp string) (string, int) {
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
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(resp))
				time.Sleep(10 * time.Second)
			}(c)
		}
	}()
	a := l.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

func TestRawHTTPStopsAtFraming(t *testing.T) {
	cases := []struct {
		name, method, resp string
		status             int
		body               string
	}{
		{"content-length", "GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 200, "ok"},
		{"chunked", "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n3;x=y\r\n!!!\r\n0\r\n\r\n", 200, "ok!!!"},
		{"chunked-trailer", "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-T: 1\r\n\r\n", 200, "ok"},
		{"no-content", "GET", "HTTP/1.1 204 No Content\r\n\r\n", 204, ""},
		{"head", "HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n", 200, ""},
		{"interim", "GET", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx", 200, "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := keepAliveServer(t, tc.resp)
			start := time.Now()
			resp, err := RawHTTP(context.Background(), host, port, tc.method, "/", nil, "", 5*time.Second, false)
			if err != nil {
				t.Fatal(err)
			}
			if el := time.Since(start); el > 2*time.Second {
				t.Fatalf("RawHTTP waited %s on a keep-alive server; it should stop at the end of the response", el)
			}
			if resp.Status != tc.status {
				t.Fatalf("status %d, want %d", resp.Status, tc.status)
			}
			if resp.Body != tc.body {
				t.Fatalf("body %q, want %q", resp.Body, tc.body)
			}
		})
	}
}

func TestResponseCompleteIsConservative(t *testing.T) {
	incomplete := []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-T: 1\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nxx",
		"HTTP/1.1 200 OK\r\n\r\nread until close",
		"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\nx",
		"HTTP/1.1 100 Continue\r\n\r\n",
	}
	for _, s := range incomplete {
		if responseComplete([]byte(s), "GET") {
			t.Errorf("complete(%q) = true, want false", s)
		}
	}
	if !responseComplete([]byte("HTTP/1.0 200 OK\nContent-Length: 1\n\nx"), "GET") {
		t.Error("LF-only head with Content-Length should be complete")
	}
	if !responseComplete([]byte("HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n"), "GET") {
		t.Error("304 has no body")
	}
}
