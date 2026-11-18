package docker

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// parityDaemon answers /build (recording its query) and /containers/*/wait
// with waitBody.
func parityDaemon(t *testing.T, waitBody string) (*Client, func() url.Values) {
	t.Helper()
	var mu sync.Mutex
	var build url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", "1.47")
		switch {
		case r.URL.Path == "/_ping":
			fmt.Fprint(w, "OK")
		case strings.HasSuffix(r.URL.Path, "/build"):
			mu.Lock()
			build = r.URL.Query()
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"stream":"done\n"}`)
		case strings.HasSuffix(r.URL.Path, "/wait"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, waitBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New("tcp://" + srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c, func() url.Values { mu.Lock(); defer mu.Unlock(); return build }
}

// A failed legacy-builder step must not leave its intermediate container
// behind: the build asks for rm and forcerm, like the SDK engine's ForceRemove.
func TestImageBuildForceRemovesIntermediateContainers(t *testing.T) {
	c, query := parityDaemon(t, `{}`)
	opts := engine.BuildOptions{Tags: []string{"x:1"}, Context: bytes.NewReader(nil)}
	if err := c.ImageBuild(context.Background(), opts, nil); err != nil {
		t.Fatal(err)
	}
	q := query()
	if q.Get("rm") != "1" || q.Get("forcerm") != "1" {
		t.Fatalf("build query rm=%q forcerm=%q, want both 1", q.Get("rm"), q.Get("forcerm"))
	}
}

// The daemon's wait Error is returned with the status code, as the SDK engine
// does.
func TestContainerWaitReturnsDaemonError(t *testing.T) {
	c, _ := parityDaemon(t, `{"StatusCode":137,"Error":{"Message":"removal of container c1 failed"}}`)
	code, err := c.ContainerWait(context.Background(), "c1")
	if code != 137 || err == nil || !strings.Contains(err.Error(), "removal of container c1 failed") {
		t.Fatalf("ContainerWait = %d, %v; want 137 and the daemon's error", code, err)
	}

	c, _ = parityDaemon(t, `{"StatusCode":3}`)
	if code, err := c.ContainerWait(context.Background(), "c1"); code != 3 || err != nil {
		t.Fatalf("ContainerWait = %d, %v; want 3, nil", code, err)
	}
}
