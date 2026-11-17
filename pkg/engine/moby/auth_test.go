package moby

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// TestMain points DOCKER_CONFIG at a scratch config before any test runs (the
// registryauth package caches it per process), so no test reads the real
// ~/.docker. The config's credsStore is a fake credential helper that knows
// Docker Hub and ghcr.io, as a credential helper like osxkeychain would.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "vulnsuite-dockercfg-")
	if err != nil {
		panic(err)
	}
	config := `{"auths": {"https://index.docker.io/v1/": {}, "ghcr.io": {}}}`
	if runtime.GOOS != "windows" {
		config = `{"auths": {"https://index.docker.io/v1/": {}, "ghcr.io": {}}, "credsStore": "vulnsuitetest"}`
		script := `#!/bin/sh
[ "$1" = get ] || exit 1
read -r server
case "$server" in
  https://index.docker.io/v1/) echo '{"Username":"hubuser","Secret":"HELPER-HUB-PASS"}' ;;
  ghcr.io) echo '{"Username":"<token>","Secret":"HELPER-GHCR-TOKEN"}' ;;
  *) exit 1 ;;
esac
`
		if err := os.WriteFile(filepath.Join(dir, "docker-credential-vulnsuitetest"), []byte(script), 0o755); err != nil {
			panic(err)
		}
		os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600); err != nil {
		panic(err)
	}
	os.Setenv("DOCKER_CONFIG", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// authDaemon is a fake daemon that records the registry credentials each
// request carries: X-Registry-Auth on pulls and pushes, X-Registry-Config on
// builds (every pull the build's Dockerfile makes).
func authDaemon(t *testing.T) (string, func() map[string]string) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := r.URL.Path
		decode := func(h string) string {
			raw, _ := base64.URLEncoding.DecodeString(r.Header.Get(h))
			return string(raw)
		}
		switch {
		case strings.HasSuffix(p, "/_ping"):
			w.Header().Set("API-Version", "1.51")
			fmt.Fprint(w, "OK")
			return
		case strings.HasSuffix(p, "/images/create"):
			ref := r.URL.Query().Get("fromImage")
			if tag := r.URL.Query().Get("tag"); tag != "" {
				ref += ":" + tag
			}
			// the moby client sends the normalised name
			ref = strings.TrimPrefix(ref, "docker.io/library/")
			seen["pull "+ref] = decode("X-Registry-Auth")
		case strings.HasSuffix(p, "/push"):
			seen["push "+p] = decode("X-Registry-Auth")
		case strings.HasSuffix(p, "/build"):
			io.Copy(io.Discard, r.Body)
			seen["build"] = decode("X-Registry-Config")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`+"\n")
	}))
	t.Cleanup(srv.Close)
	return "tcp://" + strings.TrimPrefix(srv.URL, "http://"), func() map[string]string {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]string{}
		for k, v := range seen {
			out[k] = v
		}
		return out
	}
}

// TestRegistryCredentialScoping checks which requests carry
// VULNSUITE_REGISTRY_USER/TOKEN: never a pull of a template-chosen image or a
// build's registry config, a push to the user's registry always, and, with
// VULNSUITE_REGISTRY set, only that registry (Docker Hub included, matched
// for bare references such as nginx:1.25).
func TestRegistryCredentialScoping(t *testing.T) {
	t.Setenv("VULNSUITE_REGISTRY_USER", "pushbot")
	t.Setenv("VULNSUITE_REGISTRY_TOKEN", "FAKE-ENV-TOKEN")
	templatePulls := []string{"registry.attacker.example/x:1", "quay.io/foo/bar:1", "nginx:1.25", "ghcr.io/someone/else:1"}
	const push = "ghcr.io/ruzfi/vulnsuite/demo:vulnerable"
	for _, tc := range []struct {
		scope    string
		envPulls map[string]bool // template pulls that may carry the env pair
		envPush  bool
	}{
		{scope: "", envPush: true},
		{scope: "docker.io", envPulls: map[string]bool{"nginx:1.25": true}},
		{scope: "ghcr.io/ruzfi/vulnsuite", envPulls: map[string]bool{"ghcr.io/someone/else:1": true}, envPush: true},
	} {
		t.Run("scope="+tc.scope, func(t *testing.T) {
			t.Setenv("VULNSUITE_REGISTRY", tc.scope)
			host, seen := authDaemon(t)
			e := newForAuthTest(t, host)
			ctx := context.Background()
			for _, ref := range templatePulls {
				if err := e.ImagePull(ctx, ref, "", io.Discard); err != nil {
					t.Fatal(err)
				}
			}
			if err := e.ImageBuild(ctx, engine.BuildOptions{Context: bytes.NewReader(nil), Tags: []string{"vulnsuite/x:y"}}, io.Discard); err != nil {
				t.Fatal(err)
			}
			if err := e.ImagePush(ctx, push, io.Discard); err != nil {
				t.Fatal(err)
			}
			got := seen()
			for _, ref := range templatePulls {
				h, ok := got["pull "+ref]
				if !ok {
					t.Fatalf("pull of %s not seen: %v", ref, got)
				}
				if has := strings.Contains(h, "FAKE-ENV-TOKEN"); has != tc.envPulls[ref] {
					t.Errorf("pull of %s: env token sent = %v, want %v (%s)", ref, has, tc.envPulls[ref], h)
				}
			}
			if runtime.GOOS != "windows" && tc.scope != "docker.io" && !strings.Contains(got["pull nginx:1.25"], "HELPER-HUB-PASS") {
				t.Errorf("a Hub pull must still get the helper's Hub credential: %q", got["pull nginx:1.25"])
			}
			if b := got["build"]; strings.Contains(b, "FAKE-ENV-TOKEN") || strings.Contains(b, "pushbot") {
				t.Errorf("build registry config carries the env pair: %s", b)
			} else if runtime.GOOS != "windows" && !strings.Contains(b, "HELPER-GHCR-TOKEN") {
				t.Errorf("build registry config lacks the helper's credentials: %q", b)
			}
			var pushAuth string
			for k, v := range got {
				if strings.HasPrefix(k, "push ") {
					pushAuth = v
				}
			}
			if has := strings.Contains(pushAuth, "FAKE-ENV-TOKEN"); has != tc.envPush {
				t.Errorf("push: env token sent = %v, want %v (%s)", has, tc.envPush, pushAuth)
			}
		})
	}
}

func newForAuthTest(t *testing.T, host string) *Engine {
	t.Helper()
	e, err := New(host)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
