package moby

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

// platformDaemon records the platform query of pull/create/inspect calls. The
// image "multi" reports the host (arm64) variant by default and, like a
// containerd image store, the amd64 one when asked for it (API 1.49+).
func platformDaemon(t *testing.T, apiVersion string) (*Engine, map[string]string) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p, q := r.URL.Path, r.URL.Query()
		switch {
		case strings.HasSuffix(p, "/_ping"):
			w.Header().Set("API-Version", apiVersion)
			fmt.Fprint(w, "OK")
		case strings.HasSuffix(p, "/images/create"):
			seen["pull"] = q.Get("platform")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"done"}`)
		case strings.HasSuffix(p, "/containers/create"):
			seen["create"] = q.Get("platform")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"Id":"c1"}`)
		case strings.HasSuffix(p, "/images/multi/json"):
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(q.Get("platform"), "amd64") {
				fmt.Fprint(w, `{"Id":"sha256:1","Os":"linux","Architecture":"amd64"}`)
				return
			}
			fmt.Fprint(w, `{"Id":"sha256:1","Os":"linux","Architecture":"arm64","Variant":"v8"}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"No such image"}`)
		}
	}))
	t.Cleanup(srv.Close)
	e, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return e, seen
}

func TestPlatformReachesDaemon(t *testing.T) {
	ctx := context.Background()
	e, seen := platformDaemon(t, "1.51")
	if err := e.ImagePull(ctx, "amd64/busybox:1.36.1", "linux/amd64", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ContainerCreate(ctx, engine.ContainerSpec{Name: "x", Image: "amd64/busybox:1.36.1", Platform: "linux/amd64"}); err != nil {
		t.Fatal(err)
	}
	if seen["pull"] != "linux/amd64" || seen["create"] != "linux/amd64" {
		t.Fatalf("platform not sent: %v", seen)
	}
	for platform, want := range map[string]bool{"": true, "linux/arm64": true, "linux/amd64": true, "linux/s390x": false} {
		if ok, err := e.ImageExists(ctx, "multi", platform); err != nil || ok != want {
			t.Errorf("ImageExists(multi, %q) = %v, %v; want %v", platform, ok, err, want)
		}
	}
	if ok, err := e.ImageExists(ctx, "absent", "linux/amd64"); err != nil || ok {
		t.Errorf("absent image: %v %v", ok, err)
	}
}

// A daemon too old to inspect a platform: a non-default platform counts as
// missing (it is then pulled), rather than failing.
func TestImageExistsOldDaemon(t *testing.T) {
	e, _ := platformDaemon(t, "1.44")
	ok, err := e.ImageExists(context.Background(), "multi", "linux/amd64")
	if err != nil || ok {
		t.Fatalf("old daemon: %v %v", ok, err)
	}
}

// Only "not found" on the platform-specific inspect means "pull it"; any other
// failure (here a daemon error, and a cancelled context) is returned rather
// than read as a missing image.
func TestImageExistsPlatformInspectErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", "1.51")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			fmt.Fprint(w, "OK")
		case r.URL.Query().Get("platform") == "":
			fmt.Fprint(w, `{"Id":"sha256:1","Os":"linux","Architecture":"arm64"}`)
		case strings.Contains(r.URL.Path, "/images/gone/"):
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"image gone was found but does not provide the specified platform"}`)
		case strings.Contains(r.URL.Path, "/images/cancel/"):
			cancel()
			<-r.Context().Done()
		default:
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"message":"store is broken"}`)
		}
	}))
	t.Cleanup(srv.Close)
	e, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := e.ImageExists(context.Background(), "gone", "linux/amd64"); ok || err != nil {
		t.Errorf("not found: %v, %v; want false, nil", ok, err)
	}
	if ok, err := e.ImageExists(context.Background(), "broken", "linux/amd64"); ok || err == nil {
		t.Errorf("daemon error: %v, %v; want the error", ok, err)
	}
	if ok, err := e.ImageExists(ctx, "cancel", "linux/amd64"); ok || err == nil {
		t.Errorf("cancelled: %v, %v; want an error", ok, err)
	}
}
