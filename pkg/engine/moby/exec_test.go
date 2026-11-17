package moby

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

// fakeDaemon answers the exec endpoints the SDK uses, hijacking the attach the
// way dockerd does. The exec writes `out` bytes, keeps running for `linger`,
// then exits with `code`; until then exec inspect reports Running, exit 0.
func fakeDaemon(t *testing.T, out int, linger time.Duration, code int) *Engine {
	t.Helper()
	var exited atomic.Bool
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/_ping"):
			w.Header().Set("API-Version", "1.47")
			fmt.Fprint(w, "OK")
		case strings.HasSuffix(p, "/containers/c1/exec"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"Id":"e1"}`)
		case strings.HasSuffix(p, "/exec/e1/start"):
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			fmt.Fprint(rw, "HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			chunk := make([]byte, 64*1024)
			for sent := 0; sent < out; sent += len(chunk) {
				if _, err := rw.Write(frame(1, chunk)); err != nil {
					return
				}
			}
			if out > 0 && out < len(chunk) {
				_, _ = rw.Write(frame(1, []byte("hi")))
			}
			_ = rw.Flush()
			// Linger like a running process. (A client half-close is not a
			// hang-up: the SDK may CloseWrite an attach with no stdin.)
			select {
			case <-time.After(linger):
			case <-stop:
				return
			}
			exited.Store(true)
		case strings.HasSuffix(p, "/exec/e1/json"):
			w.Header().Set("Content-Type", "application/json")
			if exited.Load() {
				fmt.Fprintf(w, `{"ID":"e1","Running":false,"ExitCode":%d}`, code)
			} else {
				fmt.Fprint(w, `{"ID":"e1","Running":true,"ExitCode":0}`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(stop) }) // runs before srv.Close
	e, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// The hijacked attach does not watch ctx; the exec timeout must still apply.
func TestExecHonoursTimeout(t *testing.T) {
	e := fakeDaemon(t, 1, 8*time.Second, 0)
	start := time.Now()
	_, _, err := e.ContainerExec(context.Background(), "c1", "sleep 8", 500*time.Millisecond)
	if err == nil {
		t.Fatal("a timed-out exec must return an error")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("exec took %v; the timeout was ignored", el)
	}
}

// Output past the 1 MiB cap must not make exec inspect run before the process
// exits (which reads as exit 0).
func TestExecLargeOutputReportsRealExitCode(t *testing.T) {
	e := fakeDaemon(t, 1100*1024, 300*time.Millisecond, 7)
	code, out, err := e.ContainerExec(context.Background(), "c1", "big", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
	if len(out) != execOutputCap {
		t.Fatalf("output %d bytes, want capped at %d", len(out), execOutputCap)
	}
}
