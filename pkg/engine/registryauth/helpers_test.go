package registryauth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// helperCalls returns the servers the fake helper logged, one per run.
func helperCalls(t *testing.T, logPath string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// Every build renders ConfigsHeader; with a credsStore that must not run the
// helper again for every registry on every build, nor once per concurrent
// build.
func TestHelperRunsOncePerServer(t *testing.T) {
	logPath := scratchConfig(t, `{
	  "auths": {"https://index.docker.io/v1/": {}, "ghcr.io": {}, "unknown.example.com": {}},
	  "credsStore": "fake"
	}`)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ConfigsHeader() == "" {
				t.Error("ConfigsHeader() is empty")
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 3; i++ {
		ConfigsHeader()
		if a, ok := Lookup("ghcr.io/x/y:1"); !ok || a.IdentityToken != "ghcr-token" {
			t.Fatalf("Lookup(ghcr.io) = %+v, %v", a, ok)
		}
	}
	calls := helperCalls(t, logPath)
	count := map[string]int{}
	for _, c := range calls {
		count[c]++
	}
	// unknown.example.com is a "not found" answer, which is cached as well.
	for _, server := range []string{hubAddress, "ghcr.io", "unknown.example.com"} {
		if count[server] != 1 {
			t.Errorf("helper ran %d times for %s, want once (calls: %q)", count[server], server, calls)
		}
	}
}

// auths and credHelpers keys are matched like the docker CLI's
// ConvertToHostname: scheme and path do not matter, and every Docker Hub
// spelling is Docker Hub.
func TestConfigKeysNormalised(t *testing.T) {
	logPath := scratchConfig(t, `{
	  "auths": {
	    "https://reg.example.com/v2/": {"auth": "`+basic("reguser", "regpass")+`"},
	    "http://other.example:5000/": {"auth": "`+basic("otheruser", "otherpass")+`"},
	    "index.docker.io": {"auth": "`+basic("hubplain", "hubpass")+`"}
	  },
	  "credHelpers": {"https://ghcr.io": "fake"}
	}`)
	for ref, user := range map[string]string{
		"reg.example.com/team/app:1": "reguser",
		"other.example:5000/x":       "otheruser",
		"nginx:1.25":                 "hubplain",
		"docker.io/library/redis":    "hubplain",
	} {
		a, ok := Lookup(ref)
		if !ok || a.Username != user {
			t.Errorf("Lookup(%q) = %+v, %v; want user %s", ref, a, ok, user)
		}
	}
	if a, ok := Lookup("ghcr.io/x/y"); !ok || a.IdentityToken != "ghcr-token" || a.ServerAddress != "ghcr.io" {
		t.Errorf("Lookup(ghcr.io) = %+v, %v; want the credHelpers helper's token", a, ok)
	}
	got := Configs()
	want := map[string]string{"reg.example.com": "reguser", "other.example:5000": "otheruser", hubAddress: "hubplain"}
	for k, u := range want {
		if got[k].Username != u || got[k].ServerAddress != k {
			t.Errorf("Configs()[%q] = %+v, want user %s", k, got[k], u)
		}
	}
	if got["ghcr.io"].IdentityToken != "ghcr-token" {
		t.Errorf("Configs()[ghcr.io] = %+v", got["ghcr.io"])
	}
	if len(got) != 4 {
		t.Errorf("Configs() = %+v, want 4 registries", got)
	}
	// The helper is asked for the registry's host, once for both lookups.
	if calls := helperCalls(t, logPath); len(calls) != 1 || calls[0] != "ghcr.io" {
		t.Errorf("helper calls = %q", calls)
	}
}

func TestNormalizeKey(t *testing.T) {
	for in, want := range map[string]string{
		"reg.example.com":                "reg.example.com",
		"https://reg.example.com/v2/":    "reg.example.com",
		"http://localhost:5000":          "localhost:5000",
		"reg.example.com/path":           "reg.example.com",
		"https://index.docker.io/v1/":    hubAddress,
		"index.docker.io":                hubAddress,
		"docker.io":                      hubAddress,
		"https://registry-1.docker.io/x": hubAddress,
		"ghcr.io":                        "ghcr.io",
	} {
		if got := normalizeKey(in); got != want {
			t.Errorf("normalizeKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// slowHelper installs docker-credential-slow, which logs the server it is
// asked about and then hangs (in a child process holding stdout, like a
// keychain prompt would).
func slowHelper(t *testing.T) (logPath string) {
	t.Helper()
	dir := os.Getenv("DOCKER_CONFIG")
	logPath = filepath.Join(dir, "slow.log")
	script := "#!/bin/sh\nread -r server\necho \"$server\" >> \"" + logPath + "\"\nsleep 30\n"
	if err := os.WriteFile(filepath.Join(dir, "bin", "docker-credential-slow"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return logPath
}

// A hanging credential helper is killed after helperTimeout instead of
// blocking the build forever, and its failure is cached.
func TestHelperTimeout(t *testing.T) {
	scratchConfig(t, `{"auths": {"ghcr.io": {}}, "credsStore": "slow"}`)
	logPath := slowHelper(t)
	old := helperTimeout
	helperTimeout = time.Second
	t.Cleanup(func() { helperTimeout = old })

	start := time.Now()
	if h := ConfigsHeader(); h != "" {
		t.Errorf("ConfigsHeader() = %q, want empty", h)
	}
	if _, ok := Lookup("ghcr.io/x"); ok {
		t.Error("Lookup succeeded through a hanging helper")
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Errorf("took %v with a hanging helper", d)
	}
	if calls := helperCalls(t, logPath); len(calls) != 1 {
		t.Errorf("helper calls = %q, want one (the timeout is cached)", calls)
	}
}

// A cancelled context (Ctrl-C) stops a running helper, and that run is not
// cached as the registry's answer.
func TestHelperHonoursContext(t *testing.T) {
	scratchConfig(t, `{"auths": {"ghcr.io": {}}, "credsStore": "slow"}`)
	logPath := slowHelper(t)

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		start := time.Now()
		h := ConfigsHeaderContext(ctx)
		cancel()
		if h != "" {
			t.Errorf("ConfigsHeaderContext() = %q, want empty", h)
		}
		if d := time.Since(start); d > 8*time.Second {
			t.Errorf("took %v after the context ended", d)
		}
	}
	if calls := helperCalls(t, logPath); len(calls) != 2 {
		t.Errorf("helper calls = %q, want two (a cancelled run is not cached)", calls)
	}
}
