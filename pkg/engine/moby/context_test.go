package moby

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolate clears the developer's docker environment and returns a fresh
// DOCKER_CONFIG directory.
func isolate(t *testing.T) string {
	t.Helper()
	cfg := t.TempDir()
	for _, k := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"} {
		t.Setenv(k, "")
	}
	t.Setenv("DOCKER_CONFIG", cfg)
	return cfg
}

// storeContext writes a context the way the docker CLI stores it.
func storeContext(t *testing.T, cfg, name, host string, skipVerify bool) {
	t.Helper()
	sum := sha256.Sum256([]byte(name))
	meta := filepath.Join(cfg, "contexts", "meta", hex.EncodeToString(sum[:]))
	if err := os.MkdirAll(meta, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf(`{"Name":%q,"Metadata":{},"Endpoints":{"docker":{"Host":%q,"SkipTLSVerify":%v}}}`, name, host, skipVerify)
	if err := os.WriteFile(filepath.Join(meta, "meta.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pingDaemon(version string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", "1.47")
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			fmt.Fprint(w, "OK")
			return
		}
		fmt.Fprintf(w, `{"Version":%q,"ApiVersion":"1.47","Os":"linux","Arch":"amd64"}`, version)
	})
}

// With no -docker-host and no DOCKER_HOST, the SDK engine follows the docker
// context like the docker CLI and the api engine. It used to read only
// DOCKER_HOST and fall back to /var/run/docker.sock, so a context-only setup
// (Colima, a remote context) failed or silently used the local daemon.
func TestNewFollowsDockerContext(t *testing.T) {
	cfg := isolate(t)
	plain := httptest.NewServer(pingDaemon("plain"))
	defer plain.Close()
	plainHost := "tcp://" + strings.TrimPrefix(plain.URL, "http://")
	storeContext(t, cfg, "lab", plainHost, false)
	if err := os.WriteFile(filepath.Join(cfg, "config.json"), []byte(`{"currentContext":"lab"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if e.Host() != plainHost {
		t.Fatalf("currentContext: host %q, want %q", e.Host(), plainHost)
	}
	if v, err := e.Ping(context.Background()); err != nil || !strings.HasPrefix(v, "plain ") {
		t.Fatalf("ping via currentContext = %q, %v", v, err)
	}

	// DOCKER_CONTEXT names a TLS endpoint (SkipTLSVerify, as `docker context
	// create --docker host=...,skip-tls-verify=true` stores it).
	secure := httptest.NewTLSServer(pingDaemon("tls"))
	defer secure.Close()
	tlsHost := "tcp://" + strings.TrimPrefix(secure.URL, "https://")
	storeContext(t, cfg, "remote", tlsHost, true)
	t.Setenv("DOCKER_CONTEXT", "remote")
	e, err = New("")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := e.Ping(context.Background()); err != nil || !strings.HasPrefix(v, "tls ") {
		t.Fatalf("ping via TLS context = %q, %v", v, err)
	}

	// An explicit unknown context is an error, as with the docker CLI.
	t.Setenv("DOCKER_CONTEXT", "missing")
	if _, err := New(""); err == nil || !strings.Contains(err.Error(), `"missing"`) {
		t.Fatalf("unknown DOCKER_CONTEXT: %v", err)
	}

	// DOCKER_HOST wins over any context; an explicit host wins over both.
	t.Setenv("DOCKER_HOST", plainHost)
	if e, err = New(""); err != nil || e.Host() != plainHost {
		t.Fatalf("DOCKER_HOST: %v %v", e, err)
	}
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "remote")
	if e, err = New(plainHost); err != nil || e.Host() != plainHost {
		t.Fatalf("explicit host: %v %v", e, err)
	}
}
