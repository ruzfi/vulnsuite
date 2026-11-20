package docker

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Endpoint is a daemon address plus the TLS material to reach it with, as the
// docker CLI resolves it from DOCKER_HOST / DOCKER_TLS_VERIFY /
// DOCKER_CERT_PATH or from a docker context.
type Endpoint struct {
	Host string
	// Context is the docker context the endpoint came from ("" when it came
	// from the environment or the socket defaults).
	Context string
	// TLS is nil for a plain connection.
	TLS *TLSFiles
}

// TLSFiles names the PEM files for a TLS connection; an empty path is unused.
type TLSFiles struct {
	CA, Cert, Key string
	// SkipVerify disables server certificate verification (TLS without
	// DOCKER_TLS_VERIFY, or a context with SkipTLSVerify).
	SkipVerify bool
}

// configDir is the docker CLI config directory ($DOCKER_CONFIG or ~/.docker).
func configDir() string {
	if d := os.Getenv("DOCKER_CONFIG"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".docker")
}

// envTLS returns the TLS settings the environment asks for, like the docker
// CLI and the official SDK's FromEnv: TLS is on when DOCKER_TLS_VERIFY or
// DOCKER_CERT_PATH is set, the certificates come from DOCKER_CERT_PATH (default
// the config directory), and the server is verified only with
// DOCKER_TLS_VERIFY.
func envTLS() *TLSFiles {
	verify := os.Getenv("DOCKER_TLS_VERIFY") != ""
	dir := os.Getenv("DOCKER_CERT_PATH")
	if !verify && dir == "" {
		return nil
	}
	if dir == "" {
		dir = configDir()
	}
	return &TLSFiles{
		CA:         filepath.Join(dir, "ca.pem"),
		Cert:       filepath.Join(dir, "cert.pem"),
		Key:        filepath.Join(dir, "key.pem"),
		SkipVerify: !verify,
	}
}

// ResolveEndpoint resolves the daemon to talk to when no host is given, in the
// docker CLI's order: DOCKER_HOST (with the DOCKER_TLS_* environment), then the
// context named by DOCKER_CONTEXT, then the config's currentContext, then the
// local socket defaults (DefaultHost).
func ResolveEndpoint() (Endpoint, error) {
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		return Endpoint{Host: h, TLS: envTLS()}, nil
	}
	name := os.Getenv("DOCKER_CONTEXT")
	explicit := name != ""
	if !explicit {
		name = currentContext()
	}
	if name != "" && name != "default" {
		ep, err := contextEndpoint(name)
		if err == nil {
			return ep, nil
		}
		if explicit {
			return Endpoint{}, err
		}
		// A dangling currentContext: the docker CLI fails here too, but the
		// socket defaults are a friendlier fallback for a tool that never
		// needed a context before.
	}
	return Endpoint{Host: DefaultHost(), TLS: nil}, nil
}

// currentContext reads currentContext from the docker CLI config ("" when
// unset or unreadable).
func currentContext() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return ""
	}
	var cfg struct {
		CurrentContext string `json:"currentContext"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return ""
	}
	return cfg.CurrentContext
}

// contextEndpoint reads a docker context's docker endpoint from the CLI's
// context store: contexts/meta/<sha256(name)>/meta.json, with TLS material in
// contexts/tls/<sha256(name)>/docker/{ca,cert,key}.pem.
func contextEndpoint(name string) (Endpoint, error) {
	sum := sha256.Sum256([]byte(name))
	id := hex.EncodeToString(sum[:])
	dir := configDir()
	data, err := os.ReadFile(filepath.Join(dir, "contexts", "meta", id, "meta.json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Endpoint{}, fmt.Errorf("docker context %q not found (DOCKER_CONTEXT or currentContext in %s)", name, filepath.Join(dir, "config.json"))
		}
		return Endpoint{}, fmt.Errorf("docker context %q: %w", name, err)
	}
	var meta struct {
		Endpoints map[string]struct {
			Host          string `json:"Host"`
			SkipTLSVerify bool   `json:"SkipTLSVerify"`
		} `json:"Endpoints"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return Endpoint{}, fmt.Errorf("docker context %q: %w", name, err)
	}
	d, ok := meta.Endpoints["docker"]
	if !ok || d.Host == "" {
		return Endpoint{}, fmt.Errorf("docker context %q has no docker endpoint", name)
	}
	ep := Endpoint{Host: d.Host, Context: name}
	tlsDir := filepath.Join(dir, "contexts", "tls", id, "docker")
	files := &TLSFiles{SkipVerify: d.SkipTLSVerify}
	for _, f := range []struct {
		dst  *string
		name string
	}{{&files.CA, "ca.pem"}, {&files.Cert, "cert.pem"}, {&files.Key, "key.pem"}} {
		if p := filepath.Join(tlsDir, f.name); fileExists(p) {
			*f.dst = p
		}
	}
	if files.CA != "" || files.Cert != "" || files.SkipVerify {
		ep.TLS = files
	}
	return ep, nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular()
}

// TLSConfig builds the client TLS configuration from f for serverName, for
// engine clients other than this package's.
func (f *TLSFiles) TLSConfig(serverName string) (*tls.Config, error) {
	return f.tlsConfig(serverName)
}

// tlsConfig builds the client TLS configuration from f: a CA bundle when
// present (else the system roots), a client certificate when both cert and
// key are present.
func (f *TLSFiles) tlsConfig(serverName string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	cfg.InsecureSkipVerify = f.SkipVerify //nolint:gosec // the user asked for TLS without verification, as with the docker CLI
	if f.CA != "" && fileExists(f.CA) {
		pem, err := os.ReadFile(f.CA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", f.CA)
		}
		cfg.RootCAs = pool
	}
	if f.Cert != "" && f.Key != "" && fileExists(f.Cert) && fileExists(f.Key) {
		pair, err := tls.LoadX509KeyPair(f.Cert, f.Key)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	} else if !f.SkipVerify && f.Cert != "" && (fileExists(f.Cert) != fileExists(f.Key)) {
		return nil, fmt.Errorf("client certificate: need both %s and %s", f.Cert, f.Key)
	}
	return cfg, nil
}
