package cli

import (
	"os"
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
