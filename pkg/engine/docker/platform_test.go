package docker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// platformDaemon records the platform query of pull and create calls and
// reports a locally present image as linux/<arch>.
func platformDaemon(t *testing.T, arch string) (*Client, map[string]string) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/images/create"):
			seen["pull"] = r.URL.Query().Get("platform")
			fmt.Fprint(w, `{"status":"done"}`)
		case strings.HasSuffix(r.URL.Path, "/containers/create"):
			seen["create"] = r.URL.Query().Get("platform")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"Id":"c1"}`)
		case strings.HasSuffix(r.URL.Path, "/images/present/json"):
			fmt.Fprintf(w, `{"Os":"linux","Architecture":%q}`, arch)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return c, seen
}

func TestPlatformReachesDaemon(t *testing.T) {
	ctx := context.Background()
	c, seen := platformDaemon(t, "arm64")
	if err := c.ImagePull(ctx, "amd64/busybox:1.36.1", "linux/amd64", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ContainerCreate(ctx, engine.ContainerSpec{Name: "x", Image: "amd64/busybox:1.36.1", Platform: "linux/amd64"}); err != nil {
		t.Fatal(err)
	}
	if seen["pull"] != "linux/amd64" || seen["create"] != "linux/amd64" {
		t.Fatalf("platform not sent: %v", seen)
	}
	if _, err := c.ContainerCreate(ctx, engine.ContainerSpec{Name: "y", Image: "x"}); err != nil || seen["create"] != "" {
		t.Fatalf("no platform must send none: %v %v", seen, err)
	}
	for platform, want := range map[string]bool{"": true, "linux/arm64": true, "linux/amd64": false} {
		if ok, err := c.ImageExists(ctx, "present", platform); err != nil || ok != want {
			t.Errorf("ImageExists(present, %q) = %v, %v; want %v", platform, ok, err, want)
		}
	}
	if ok, err := c.ImageExists(ctx, "absent", ""); err != nil || ok {
		t.Errorf("absent image: %v %v", ok, err)
	}
}
