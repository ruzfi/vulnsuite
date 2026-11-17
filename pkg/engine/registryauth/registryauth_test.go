package registryauth

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func envCreds(t *testing.T, scope string) {
	t.Helper()
	// An empty docker config, so only the env credentials are in play.
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	resetConfig()
	t.Cleanup(resetConfig)
	setEnvPair(t, scope)
}

// setEnvPair sets the env pair, scoped by VULNSUITE_REGISTRY=scope, without
// touching the docker config.
func setEnvPair(t *testing.T, scope string) {
	t.Helper()
	t.Setenv("VULNSUITE_REGISTRY_USER", "pushbot")
	t.Setenv("VULNSUITE_REGISTRY_TOKEN", "FAKE-TOKEN")
	t.Setenv("VULNSUITE_REGISTRY", scope)
}

func decode(t *testing.T, h string) Config {
	t.Helper()
	b, err := base64.URLEncoding.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// templateRefs are images a (possibly hostile) template can make vulnsuite pull.
var templateRefs = []string{
	"registry.attacker.example/x:1",
	"nginx:1.25",
	"quay.io/foo/bar",
	"registry.example.test:5000/a",
	"ghcr.io/someone/else:1",
	"localhost:5000/x",
}

func TestEnvCredsNeverSentOnPullsByDefault(t *testing.T) {
	envCreds(t, "")
	for _, ref := range templateRefs {
		if h := For(ref); h != "" {
			t.Errorf("pull of %s carried credentials: %+v", ref, decode(t, h))
		}
	}
}

func TestEnvCredsSentToPushTarget(t *testing.T) {
	envCreds(t, "")
	h := ForPush("ghcr.io/ruzfi/vulnsuite/demo:vulnerable")
	if h == "" {
		t.Fatal("push must carry the env credentials")
	}
	if c := decode(t, h); c.Username != "pushbot" || c.Password != "FAKE-TOKEN" || c.ServerAddress != "ghcr.io" {
		t.Fatalf("push credential: %+v", c)
	}
}

func TestEnvCredsScopedByVulnsuiteRegistry(t *testing.T) {
	for _, scope := range []string{"ghcr.io", "ghcr.io/ruzfi/vulnsuite", "https://ghcr.io/", "GHCR.IO"} {
		envCreds(t, scope)
		// pulls and pushes to the named registry get the credential
		if For("ghcr.io/ruzfi/vulnsuite/demo:patched") == "" {
			t.Errorf("%s: pull from the scoped registry must carry credentials", scope)
		}
		if ForPush("ghcr.io/ruzfi/vulnsuite/demo:patched") == "" {
			t.Errorf("%s: push to the scoped registry must carry credentials", scope)
		}
		// nothing else does, not even a push
		for _, ref := range templateRefs {
			if ref == "ghcr.io/someone/else:1" {
				continue // same registry host the token belongs to
			}
			if For(ref) != "" || ForPush(ref) != "" {
				t.Errorf("%s: %s must not carry credentials", scope, ref)
			}
		}
	}
}

func TestEnvCredsScopedToDockerHubAliases(t *testing.T) {
	hubRefs := []string{
		"nginx:1.25",
		"nginx",
		"postgres@sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
		"library/nginx:1.25",
		"ruzfi/x:1",
		"docker.io/library/nginx",
		"index.docker.io/ruzfi/x",
		"registry-1.docker.io/library/nginx:1.25",
	}
	for _, scope := range []string{"docker.io", "DOCKER.IO", "index.docker.io", "registry-1.docker.io", "docker.io/ruzfi", "https://index.docker.io/v1/", "ruzfi"} {
		envCreds(t, scope)
		for _, ref := range hubRefs {
			if For(ref) == "" || ForPush(ref) == "" {
				t.Errorf("%s: %s is Docker Hub and must carry credentials", scope, ref)
			}
			if c, ok := Lookup(ref); !ok || c.ServerAddress != hubAddress {
				t.Errorf("%s: Lookup(%s) = %+v, %v; want the env pair keyed %s", scope, ref, c, ok, hubAddress)
			}
		}
		for _, ref := range []string{"ghcr.io/x/y", "registry.attacker.example/x", "localhost:5000/x", "quay.io/foo/bar"} {
			if For(ref) != "" || ForPush(ref) != "" {
				t.Errorf("%s: %s is not Docker Hub and must not carry credentials", scope, ref)
			}
		}
	}
	envCreds(t, "localhost:5000")
	if ForPush("localhost:5000/vs/demo:vulnerable") == "" || For("localhost:5001/x") != "" || For("nginx:1.25") != "" {
		t.Error("host:port scope must match exactly")
	}
}

func TestScopeRegistry(t *testing.T) {
	for in, want := range map[string]string{
		"":                            "",
		"docker.io":                   hubAddress,
		"index.docker.io":             hubAddress,
		"https://index.docker.io/v1/": hubAddress,
		"docker.io/ruzfi/vulnsuite":   hubAddress,
		"ruzfi":                       hubAddress, // -registry ruzfi pushes to Hub
		"GHCR.io":                     "ghcr.io",
		"ghcr.io/ruzfi/vulnsuite":     "ghcr.io",
		"http://localhost:5000/":      "localhost:5000",
		"localhost":                   "localhost",
		"registry.example.com:8443/a": "registry.example.com:8443",
	} {
		t.Setenv("VULNSUITE_REGISTRY", in)
		if got := scopeRegistry(); got != want {
			t.Errorf("VULNSUITE_REGISTRY=%q: scopeRegistry() = %q, want %q", in, got, want)
		}
	}
}

// The env pair is for the user's push registry. A build's X-Registry-Config
// (every pull a template's Dockerfile makes) must never carry it, even when a
// credential helper resolves other registries and VULNSUITE_REGISTRY scopes
// the pair to one of them.
func TestConfigsNeverCarryEnvCreds(t *testing.T) {
	for _, scope := range []string{"", "docker.io", "ghcr.io", "registry.example.com"} {
		scratchConfig(t, `{
		  "auths": {"https://index.docker.io/v1/": {}, "ghcr.io": {}, "registry.example.com": {"auth": "`+basic("plainuser", "plainpass")+`"}},
		  "credsStore": "fake"
		}`)
		setEnvPair(t, scope)
		for k, c := range Configs() {
			if c.Username == "pushbot" || c.Password == "FAKE-TOKEN" || c.IdentityToken == "FAKE-TOKEN" {
				t.Errorf("scope %q: Configs()[%q] carries the env pair: %+v", scope, k, c)
			}
		}
		raw, _ := base64.URLEncoding.DecodeString(ConfigsHeader())
		if strings.Contains(string(raw), "FAKE-TOKEN") {
			t.Errorf("scope %q: X-Registry-Config carries the env pair", scope)
		}
		// Pulls of template-chosen images get the helper's credential for
		// their own registry, never the env pair.
		for _, ref := range []string{"registry.attacker.example/x:1", "quay.io/foo/bar"} {
			if h := For(ref); h != "" {
				t.Errorf("scope %q: pull of %s carried %+v", scope, ref, decode(t, h))
			}
		}
		if c, ok := Lookup("ghcr.io/someone/x"); scope != "ghcr.io" && (!ok || c.IdentityToken != "ghcr-token") {
			t.Errorf("scope %q: ghcr.io pull = %+v, %v; want the helper's token", scope, c, ok)
		}
	}
}
