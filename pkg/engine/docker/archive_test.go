package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// archiveDaemon answers /containers/c1/archive with stat (raw header value) and
// body, recording each request as "METHOD path=<path>".
func archiveDaemon(t *testing.T, stat string, body []byte) (*Client, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", "1.47")
		switch {
		case r.URL.Path == "/_ping":
		case strings.HasSuffix(r.URL.Path, "/containers/c1/archive"):
			mu.Lock()
			seen = append(seen, r.Method+" path="+r.URL.Query().Get("path"))
			mu.Unlock()
			w.Header().Set("X-Docker-Container-Path-Stat", stat)
			if r.Method == http.MethodGet {
				w.Write(body)
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
	return c, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// A hostile archive yields only the directory's own regular files, and the
// path sent is cleaned so a trailing slash cannot make the daemon follow a
// symlinked directory.
func TestContainerReadDirUntrustedArchive(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range []struct{ name, data string }{{"asan/a", "report"}, {"../../etc/x", "no"}, {"asan/sub/b", "no"}, {"/asan/c", "no"}} {
		tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), Typeflag: tar.TypeReg})
		tw.Write([]byte(e.data))
	}
	tw.WriteHeader(&tar.Header{Name: "asan/l", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
	tw.Close()
	// mode 2148532735 = os.ModeDir|os.ModeSticky|0777, as dockerd sends it.
	c, seen := archiveDaemon(t, b64(`{"name":"asan","mode":2148532735}`), buf.Bytes())
	got, err := c.ContainerReadDir(context.Background(), "c1", "/var/log/asan/", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got["a"].Data) != "rep" || got["a"].Size != 6 {
		t.Fatalf("ContainerReadDir = %v; want only a, cut to 3 bytes", got)
	}
	if s := seen(); len(s) != 1 || s[0] != "GET path=/var/log/asan" {
		t.Fatalf("requests = %q; want one GET for the cleaned path", s)
	}
}

func TestContainerStatPathHeader(t *testing.T) {
	c, seen := archiveDaemon(t, b64(`{"name":"asan","mode":2148532735}`), nil)
	mode, err := c.ContainerStatPath(context.Background(), "c1", "/var/log/asan")
	if err != nil || mode.String() != "dtrwxrwxrwx" {
		t.Fatalf("ContainerStatPath = %v, %v; want dtrwxrwxrwx", mode, err)
	}
	if s := seen(); len(s) != 1 || s[0] != "HEAD path=/var/log/asan" {
		t.Fatalf("requests = %q; want one HEAD", s)
	}
	for _, bad := range []string{"", "!!!", b64("not json")} {
		c, _ := archiveDaemon(t, bad, nil)
		if _, err := c.ContainerStatPath(context.Background(), "c1", "/x"); err == nil {
			t.Errorf("stat header %q decoded without error", bad)
		}
		if _, err := c.ContainerReadDir(context.Background(), "c1", "/x", 1); err == nil {
			t.Errorf("read with stat header %q succeeded", bad)
		}
	}
	// A path that is not a directory is not read as one.
	c, _ = archiveDaemon(t, b64(`{"name":"l","mode":134218239}`), nil) // os.ModeSymlink|0777
	if _, err := c.ContainerReadDir(context.Background(), "c1", "/l", 1); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("reading a symlink as a directory = %v; want an error", err)
	}
}
