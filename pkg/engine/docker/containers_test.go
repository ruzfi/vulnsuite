package docker

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func frame(stream byte, p []byte) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(p)))
	return append(h, p...)
}

// fakeExecDaemon answers the three exec endpoints. The exec writes `out` bytes,
// then keeps running for `linger` before exiting with `code`; until then exec
// inspect reports Running with ExitCode 0, as the real daemon does.
func fakeExecDaemon(t *testing.T, out int, linger time.Duration, code int) *Client {
	t.Helper()
	var exited atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/containers/c1/exec"):
			fmt.Fprint(w, `{"Id":"e1"}`)
		case strings.HasSuffix(r.URL.Path, "/exec/e1/start"):
			w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
			chunk := make([]byte, 64*1024)
			for sent := 0; sent < out; sent += len(chunk) {
				if _, err := w.Write(frame(1, chunk)); err != nil {
					return
				}
			}
			w.(http.Flusher).Flush()
			select {
			case <-time.After(linger):
			case <-r.Context().Done():
				return
			}
			exited.Store(true)
		case strings.HasSuffix(r.URL.Path, "/exec/e1/json"):
			if exited.Load() {
				fmt.Fprintf(w, `{"Running":false,"ExitCode":%d}`, code)
			} else {
				fmt.Fprint(w, `{"Running":true,"ExitCode":0}`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Output past the 1 MiB cap must not make exec inspect run before the process
// exits (which reads as exit 0).
func TestExecLargeOutputReportsRealExitCode(t *testing.T) {
	c := fakeExecDaemon(t, 1100*1024, 300*time.Millisecond, 7)
	code, out, err := c.ContainerExec(context.Background(), "c1", "big", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
	if len(out) != 1<<20 {
		t.Fatalf("output %d bytes, want capped at 1 MiB", len(out))
	}
}

func TestExecTimeout(t *testing.T) {
	c := fakeExecDaemon(t, 10, 5*time.Second, 0)
	start := time.Now()
	_, _, err := c.ContainerExec(context.Background(), "c1", "sleep", 300*time.Millisecond)
	if err == nil {
		t.Fatal("a timed-out exec must return an error")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("exec timeout not honoured: %v", el)
	}
}

func TestDemuxStopsAtCapWithoutDrain(t *testing.T) {
	var s []byte
	for i := 0; i < 4; i++ {
		s = append(s, frame(1, []byte("abcd"))...)
	}
	if got := demux(strings.NewReader(string(s)), 6, false); got != "abcdab" {
		t.Fatalf("got %q", got)
	}
	if got := demux(strings.NewReader(string(s)), 100, true); got != strings.Repeat("abcd", 4) {
		t.Fatalf("got %q", got)
	}
}
