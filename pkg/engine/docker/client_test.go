package docker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeDaemon mimics a daemon that advertises apiVersion on /_ping (none when
// empty) and, like Docker 29.0-29.2, rejects versioned requests below minVersion.
type fakeDaemon struct {
	*httptest.Server
	mu    sync.Mutex
	pings int
	paths []string
}

func newFakeDaemon(t *testing.T, apiVersion, minVersion string) *fakeDaemon {
	t.Helper()
	d := &fakeDaemon{}
	d.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if apiVersion != "" {
			w.Header().Set("API-Version", apiVersion)
		}
		if r.URL.Path == "/_ping" {
			d.pings++
			fmt.Fprint(w, "OK")
			return
		}
		d.paths = append(d.paths, r.URL.Path)
		v, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v"), "/")
		if _, _, ok := parseVersion(v); !ok {
			http.Error(w, `{"message":"page not found"}`, http.StatusNotFound)
			return
		}
		if versionLess(v, minVersion) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"message":"client version %s is too old. Minimum supported API version is %s, please upgrade your client to a newer version"}`, v, minVersion)
			return
		}
		fmt.Fprintf(w, `{"Version":"29.2.1","ApiVersion":%q,"Os":"linux","Arch":"arm64"}`, apiVersion)
	}))
	t.Cleanup(d.Close)
	return d
}

func newTestClient(t *testing.T, d *fakeDaemon) *Client {
	t.Helper()
	c, err := New("tcp://" + d.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNegotiateAPIVersion(t *testing.T) {
	for _, tc := range []struct {
		name, server, min, wantPrefix string
	}{
		{"docker 29.2 (min 1.44)", "1.52", "1.44", "/v" + MaxAPIVersion + "/"},
		{"older daemon", "1.43", "1.12", "/v1.43/"},
		{"server equals max", MaxAPIVersion, "1.24", "/v" + MaxAPIVersion + "/"},
		{"no header", "", "1.24", "/v" + MinAPIVersion + "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DOCKER_API_VERSION", "")
			d := newFakeDaemon(t, tc.server, tc.min)
			c := newTestClient(t, d)
			for i := 0; i < 3; i++ {
				if _, err := c.Ping(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if d.pings != 1 {
				t.Errorf("/_ping called %d times, want once", d.pings)
			}
			for _, p := range d.paths {
				if !strings.HasPrefix(p, tc.wantPrefix) {
					t.Errorf("request to %s, want prefix %s", p, tc.wantPrefix)
				}
			}
		})
	}
}

func TestDockerAPIVersionEnvSkipsNegotiation(t *testing.T) {
	t.Setenv("DOCKER_API_VERSION", "v1.45")
	d := newFakeDaemon(t, "1.52", "1.44")
	c := newTestClient(t, d)
	if _, err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.pings != 0 || len(d.paths) != 1 || d.paths[0] != "/v1.45/version" {
		t.Errorf("pings=%d paths=%v, want no ping and /v1.45/version", d.pings, d.paths)
	}
}

func TestOldPinnedVersionSurfacesDaemonError(t *testing.T) {
	t.Setenv("DOCKER_API_VERSION", "1.41")
	d := newFakeDaemon(t, "1.52", "1.44")
	_, err := newTestClient(t, d).Ping(context.Background())
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Errorf("err = %v, want the daemon's too-old error", err)
	}
}

func TestNegotiate(t *testing.T) {
	for in, want := range map[string]string{
		"":      MinAPIVersion,
		"junk":  MinAPIVersion,
		"1.40":  "1.40",
		"1.44":  "1.44",
		"v1.45": "1.45",
		"1.56":  MaxAPIVersion,
		"2.0":   MaxAPIVersion,
		"1.100": MaxAPIVersion,
	} {
		if got := negotiate(in); got != want {
			t.Errorf("negotiate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNegotiationRetriesAfterDialFailure(t *testing.T) {
	t.Setenv("DOCKER_API_VERSION", "")
	c, err := New("tcp://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected a dial error")
	}
	if c.version != "" {
		t.Errorf("a failed ping must not fix the version (got %q)", c.version)
	}
}
