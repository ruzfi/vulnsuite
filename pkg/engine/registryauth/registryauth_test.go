package registryauth

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestRegistryOf(t *testing.T) {
	const digest = "sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac"
	for _, tc := range []struct{ ref, want string }{
		{"nginx", hubAddress},
		{"nginx:1.25", hubAddress},
		{"postgres@" + digest, hubAddress},
		{"postgres:16@" + digest, hubAddress},
		{"library/nginx:1.25", hubAddress},
		{"bitnami/redis:7", hubAddress},
		{"docker.io/library/nginx", hubAddress},
		{"docker.io/nginx:1.25", hubAddress},
		{"index.docker.io/library/nginx", hubAddress},
		{"registry-1.docker.io/library/nginx:1.25", hubAddress},
		{"ghcr.io/ruzfi/x", "ghcr.io"},
		{"ghcr.io/ruzfi/x:1@" + digest, "ghcr.io"},
		{"localhost/x", "localhost"},
		{"localhost:5000/x", "localhost:5000"},
		{"localhost:5000/x:tag", "localhost:5000"},
		{"registry.example.com:8443/team/app@" + digest, "registry.example.com:8443"},
		{"[::1]:5000/x", "[::1]:5000"},
		{"10.0.0.1:5000/x:1", "10.0.0.1:5000"},
		// not valid references: the fallback still finds the host
		{"ghcr.io/Ruzfi/X", "ghcr.io"},
		{"Nginx:1.25", hubAddress},
	} {
		if got := registryOf(tc.ref); got != tc.want {
			t.Errorf("registryOf(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

// scratchConfig points DOCKER_CONFIG at a temp dir holding config, puts a
// fake docker-credential-fake helper first on PATH, and resets the cached
// config. The helper answers for "https://index.docker.io/v1/" and ghcr.io
// and logs every server it is asked about to calls.log.
func scratchConfig(t *testing.T, config string) (logPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake credential helper is a shell script")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath = filepath.Join(dir, "calls.log")
	script := `#!/bin/sh
[ "$1" = get ] || exit 1
read -r server
echo "$server" >> "` + logPath + `"
case "$server" in
  https://index.docker.io/v1/) echo '{"ServerURL":"'"$server"'","Username":"hubuser","Secret":"hubpass"}' ;;
  ghcr.io) echo '{"ServerURL":"ghcr.io","Username":"<token>","Secret":"ghcr-token"}' ;;
  *) echo "credentials not found in native keychain"; exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "docker-credential-fake"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dir)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("VULNSUITE_REGISTRY_USER", "")
	t.Setenv("VULNSUITE_REGISTRY_TOKEN", "")
	resetConfig()
	t.Cleanup(resetConfig)
	return logPath
}

func resetConfig() {
	cfgOnce = sync.Once{}
	cfg = nil
}

func basic(u, p string) string { return base64.StdEncoding.EncodeToString([]byte(u + ":" + p)) }

func TestConfigsResolveThroughCredsStore(t *testing.T) {
	scratchConfig(t, `{
	  "auths": {
	    "https://index.docker.io/v1/": {},
	    "ghcr.io": {},
	    "registry.example.com": {"auth": "`+basic("plainuser", "plainpass")+`"},
	    "unknown.example.com": {}
	  },
	  "credsStore": "fake"
	}`)
	got := Configs()
	want := map[string]Config{
		hubAddress:             {Username: "hubuser", Password: "hubpass", ServerAddress: hubAddress},
		"ghcr.io":              {IdentityToken: "ghcr-token", ServerAddress: "ghcr.io"},
		"registry.example.com": {Username: "plainuser", Password: "plainpass", ServerAddress: "registry.example.com"},
	}
	if len(got) != len(want) {
		t.Fatalf("Configs() = %+v, want %+v", got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("Configs()[%q] = %+v, want %+v", k, got[k], w)
		}
	}
	if ConfigsHeader() == "" {
		t.Error("ConfigsHeader() is empty")
	}
}

func TestConfigsResolveThroughCredHelpers(t *testing.T) {
	logPath := scratchConfig(t, `{
	  "auths": {"registry.example.com": {"auth": "`+basic("plainuser", "plainpass")+`"}},
	  "credHelpers": {"ghcr.io": "fake", "missing.example.com": "nosuchhelper"}
	}`)
	got := Configs()
	if a := got["ghcr.io"]; a.IdentityToken != "ghcr-token" {
		t.Errorf("ghcr.io = %+v, want the helper's token", a)
	}
	if a := got["registry.example.com"]; a.Username != "plainuser" {
		t.Errorf("registry.example.com = %+v, want the plain auth", a)
	}
	if _, ok := got["missing.example.com"]; ok {
		t.Error("a registry whose helper is missing must be skipped")
	}
	b, err := os.ReadFile(logPath)
	if err != nil || string(b) != "ghcr.io\n" {
		t.Errorf("helper calls = %q (%v), want only ghcr.io", b, err)
	}
}

func TestConfigsPlainAuthsOnly(t *testing.T) {
	scratchConfig(t, `{"auths": {"registry.example.com": {"auth": "`+basic("u", "p")+`"}, "empty.example.com": {}}}`)
	got := Configs()
	if len(got) != 1 || got["registry.example.com"].Password != "p" {
		t.Errorf("Configs() = %+v", got)
	}
}

func TestLookupHubRefsUseHubKey(t *testing.T) {
	logPath := scratchConfig(t, `{"auths": {"https://index.docker.io/v1/": {}}, "credsStore": "fake"}`)
	for _, ref := range []string{"nginx:1.25", "postgres@sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac", "docker.io/library/nginx"} {
		a, ok := Lookup(ref)
		if !ok || a.Username != "hubuser" || a.ServerAddress != hubAddress {
			t.Errorf("Lookup(%q) = %+v, %v; want the hub credential", ref, a, ok)
		}
	}
	b, _ := os.ReadFile(logPath)
	if want := hubAddress + "\n" + hubAddress + "\n" + hubAddress + "\n"; string(b) != want {
		t.Errorf("helper asked for %q, want %q", b, want)
	}
}
