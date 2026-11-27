package registryauth

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #153: a failing credential helper is reported on stderr (helper, server,
// failure), never with its output; "credentials not found" is no failure.
func TestHelperFailureWarns(t *testing.T) {
	scratchConfig(t, `{"auths": {"ghcr.io": {}, "quay.io": {}, "unknown.example.com": {}},
	  "credHelpers": {"ghcr.io": "broken", "quay.io": "absent"}, "credsStore": "fake"}`)
	dir := os.Getenv("DOCKER_CONFIG")
	script := "#!/bin/sh\nread -r server\necho 'hunter2-secret' >&2\necho '{\"Secret\":\"hunter2-secret\"' \nexit 3\n"
	if err := os.WriteFile(filepath.Join(dir, "bin", "docker-credential-broken"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	old := Warnings
	Warnings = &buf
	warned.Clear()
	t.Cleanup(func() { Warnings = old; warned.Clear() })

	Configs()
	Configs() // once per helper and server
	got := buf.String()
	for _, want := range []string{
		"docker-credential-broken for ghcr.io failed (exit status 3)",
		"docker-credential-absent for quay.io is not installed",
	} {
		if strings.Count(got, want) != 1 {
			t.Errorf("warnings lack (once) %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "hunter2") {
		t.Errorf("a warning printed the helper's output:\n%s", got)
	}
	if strings.Contains(got, "unknown.example.com") {
		t.Errorf("credentials not found must not warn:\n%s", got)
	}
}
