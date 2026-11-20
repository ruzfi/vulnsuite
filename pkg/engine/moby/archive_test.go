package moby

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

	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", "1.47")
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			w.Write([]byte("OK"))
		case strings.HasSuffix(r.URL.Path, "/containers/c1/archive"):
			mu.Lock()
			seen = append(seen, r.Method+" path="+r.URL.Query().Get("path"))
			mu.Unlock()
			// mode 2148532735 = os.ModeDir|os.ModeSticky|0777, as dockerd sends it.
			w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString([]byte(`{"name":"asan","mode":2148532735}`)))
			if r.Method == http.MethodGet {
				w.Write(buf.Bytes())
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	e, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Client().Close()

	got, err := e.ContainerReadDir(context.Background(), "c1", "/var/log/asan/", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got["a"].Data) != "rep" || got["a"].Size != 6 {
		t.Fatalf("ContainerReadDir = %v; want only a, cut to 3 bytes", got)
	}
	mode, err := e.ContainerStatPath(context.Background(), "c1", "/var/log/asan/.")
	if err != nil || mode.String() != "dtrwxrwxrwx" {
		t.Fatalf("ContainerStatPath = %v, %v; want dtrwxrwxrwx", mode, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"GET path=/var/log/asan", "HEAD path=/var/log/asan"}; strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %q; want %q (cleaned paths)", seen, want)
	}
}
