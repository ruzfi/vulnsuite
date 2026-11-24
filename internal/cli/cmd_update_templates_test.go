package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/templates"
)

// update-templates resolves its directory like every other command, so
// $VULNSUITE_TEMPLATES is honoured, and it refuses to replace a directory it
// did not install. Nothing here reaches the network: the refusal happens
// before any download.
func TestUpdateTemplatesHonoursEnvAndRefusesUnrelatedDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(t.TempDir())
	dir := t.TempDir()
	keep := filepath.Join(dir, "important.txt")
	if err := os.WriteFile(keep, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(templates.EnvDir, dir)

	code, _, errOut := run(t, nil, "update-templates")
	if code == ExitOK || !strings.Contains(errOut, "refusing to replace "+dir) || !strings.Contains(errOut, "-force") {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, templates.DefaultDirName)); !os.IsNotExist(err) {
		t.Fatalf("default dir must not be touched when $%s is set: %v", templates.EnvDir, err)
	}
}

// #147 item 2: run from inside an application repository that holds a
// vulnsuite contract, update-templates must not pull (or with -ref, detach)
// that repository: it was found from the working directory, and its origin
// is not the templates repository.
func TestUpdateTemplatesRefusesForeignCheckoutFoundFromCwd(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv(templates.EnvDir, "")
	app := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", app}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("remote", "add", "origin", "https://github.com/acme/app.git")
	sec := filepath.Join(app, "security", "x")
	if err := os.MkdirAll(sec, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "contract.yaml"), []byte("apiVersion: vulnsuite/v1\nkind: Target\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sec)
	for _, args := range [][]string{{"update-templates"}, {"update-templates", "-ref", "main"}} {
		code, _, errOut := run(t, nil, args...)
		if code == ExitOK || !strings.Contains(errOut, "refusing to update") || !strings.Contains(errOut, "acme/app") {
			t.Fatalf("%v: code=%d stderr=%s", args, code, errOut)
		}
	}
	if _, err := os.Stat(filepath.Join(home, templates.DefaultDirName)); !os.IsNotExist(err) {
		t.Fatalf("default dir must not be created: %v", err)
	}
}
