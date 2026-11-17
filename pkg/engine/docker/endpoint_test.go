package docker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clearDockerEnv isolates a test from the developer's docker environment.
func clearDockerEnv(t *testing.T) string {
	t.Helper()
	cfg := t.TempDir()
	for _, k := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"} {
		t.Setenv(k, "")
	}
	t.Setenv("DOCKER_CONFIG", cfg)
	return cfg
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// tlsDaemon is a daemon that demands a client certificate, plus a cert dir in
// the docker CLI layout (ca.pem, cert.pem, key.pem) that satisfies it.
func tlsDaemon(t *testing.T) (addr, certDir string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vulnsuite-test-client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, _ := x509.ParseCertificate(der)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("API-Version", "1.47")
		if r.URL.Path == "/_ping" {
			fmt.Fprint(w, "OK")
			return
		}
		fmt.Fprint(w, `{"Version":"29.0.0","ApiVersion":"1.47","Os":"linux","Arch":"amd64"}`)
	}))
	pool := x509.NewCertPool()
	pool.AddCert(clientCert)
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	certDir = t.TempDir()
	writePEM(t, filepath.Join(certDir, "ca.pem"), "CERTIFICATE", srv.Certificate().Raw)
	writePEM(t, filepath.Join(certDir, "cert.pem"), "CERTIFICATE", der)
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(certDir, "key.pem"), "EC PRIVATE KEY", kder)
	return strings.TrimPrefix(srv.URL, "https://"), certDir
}

func TestTCPHostWithTLSVerify(t *testing.T) {
	clearDockerEnv(t)
	addr, certDir := tlsDaemon(t)
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	t.Setenv("DOCKER_CERT_PATH", certDir)
	t.Setenv("DOCKER_HOST", "tcp://"+addr)
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping over TLS: %v", err)
	}

	// Without the TLS environment the client speaks plain http and fails.
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	plain, err := New("tcp://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Ping(context.Background()); err == nil {
		t.Fatal("plain http to a TLS daemon should fail")
	}

	// Verification with a CA that did not sign the server fails.
	other := t.TempDir()
	for _, f := range []string{"cert.pem", "key.pem"} {
		b, _ := os.ReadFile(filepath.Join(certDir, f))
		_ = os.WriteFile(filepath.Join(other, f), b, 0o600)
	}
	b, _ := os.ReadFile(filepath.Join(certDir, "cert.pem")) // a CA that is not the server's
	_ = os.WriteFile(filepath.Join(other, "ca.pem"), b, 0o600)
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	t.Setenv("DOCKER_CERT_PATH", other)
	bad, err := New("tcp://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Ping(context.Background()); err == nil {
		t.Fatal("an untrusted server certificate must fail with DOCKER_TLS_VERIFY")
	}
}

// writeContext stores a context the way the docker CLI does.
func writeContext(t *testing.T, cfg, name, host string, skipVerify bool, tlsFiles map[string][]byte) {
	t.Helper()
	sum := sha256.Sum256([]byte(name))
	id := hex.EncodeToString(sum[:])
	meta := filepath.Join(cfg, "contexts", "meta", id)
	if err := os.MkdirAll(meta, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf(`{"Name":%q,"Metadata":{},"Endpoints":{"docker":{"Host":%q,"SkipTLSVerify":%v}}}`, name, host, skipVerify)
	if err := os.WriteFile(filepath.Join(meta, "meta.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(tlsFiles) > 0 {
		dir := filepath.Join(cfg, "contexts", "tls", id, "docker")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for n, b := range tlsFiles {
			if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestResolveEndpointContexts(t *testing.T) {
	cfg := clearDockerEnv(t)
	writeContext(t, cfg, "lab", "unix:///tmp/lab.sock", false, nil)
	writeContext(t, cfg, "remote", "tcp://10.0.0.5:2376", false, map[string][]byte{"ca.pem": []byte("x"), "cert.pem": []byte("x"), "key.pem": []byte("x")})
	if err := os.WriteFile(filepath.Join(cfg, "config.json"), []byte(`{"currentContext":"lab"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	ep, err := ResolveEndpoint()
	if err != nil || ep.Host != "unix:///tmp/lab.sock" || ep.Context != "lab" || ep.TLS != nil {
		t.Fatalf("currentContext: %+v %v", ep, err)
	}

	t.Setenv("DOCKER_CONTEXT", "remote")
	ep, err = ResolveEndpoint()
	if err != nil || ep.Host != "tcp://10.0.0.5:2376" || ep.TLS == nil || ep.TLS.SkipVerify ||
		!strings.HasSuffix(ep.TLS.CA, filepath.Join("docker", "ca.pem")) || ep.TLS.Key == "" {
		t.Fatalf("DOCKER_CONTEXT: %+v %+v %v", ep, ep.TLS, err)
	}

	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
	if ep, err = ResolveEndpoint(); err != nil || ep.Host != "tcp://127.0.0.1:2375" || ep.Context != "" {
		t.Fatalf("DOCKER_HOST must win: %+v %v", ep, err)
	}
	t.Setenv("DOCKER_HOST", "")

	t.Setenv("DOCKER_CONTEXT", "missing")
	if _, err := ResolveEndpoint(); err == nil || !strings.Contains(err.Error(), `"missing"`) {
		t.Fatalf("an explicit unknown context must fail: %v", err)
	}

	// "default" and a dangling currentContext fall back to the socket defaults.
	t.Setenv("DOCKER_CONTEXT", "default")
	if ep, err = ResolveEndpoint(); err != nil || ep.Context != "" || ep.Host != DefaultHost() {
		t.Fatalf("default context: %+v %v", ep, err)
	}
	t.Setenv("DOCKER_CONTEXT", "")
	_ = os.WriteFile(filepath.Join(cfg, "config.json"), []byte(`{"currentContext":"gone"}`), 0o600)
	if ep, err = ResolveEndpoint(); err != nil || ep.Host != DefaultHost() {
		t.Fatalf("dangling currentContext: %+v %v", ep, err)
	}
}

func TestContextTLSReachesDaemon(t *testing.T) {
	cfg := clearDockerEnv(t)
	addr, certDir := tlsDaemon(t)
	files := map[string][]byte{}
	for _, f := range []string{"ca.pem", "cert.pem", "key.pem"} {
		b, err := os.ReadFile(filepath.Join(certDir, f))
		if err != nil {
			t.Fatal(err)
		}
		files[f] = b
	}
	writeContext(t, cfg, "tls-lab", "tcp://"+addr, false, files)
	t.Setenv("DOCKER_CONTEXT", "tls-lab")
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping via context: %v", err)
	}
	if c.Host() != "tcp://"+addr {
		t.Fatalf("host %q", c.Host())
	}
}
