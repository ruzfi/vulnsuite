package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/runner"
)

// TestBuildContextSymlinksAndDockerignore builds a local context through a
// real daemon (#47 item 7): a symlink arrives as a symlink, and .dockerignore
// keeps a file out of the image.
func TestBuildContextSymlinksAndDockerignore(t *testing.T) {
	if os.Getenv("VULNSUITE_E2E") == "" {
		t.Skip("set VULNSUITE_E2E=1 to run against a Docker daemon")
	}
	for _, kind := range []string{"sdk", "api"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			eng := daemon(t, ctx, kind)
			dir := t.TempDir()
			src := filepath.Join(dir, "src")
			must(t, os.MkdirAll(filepath.Join(src, "www"), 0o755))
			must(t, os.WriteFile(filepath.Join(src, "Dockerfile"), []byte("FROM busybox:1.36.1\nCOPY www/ /www/\n"), 0o644))
			must(t, os.WriteFile(filepath.Join(src, ".dockerignore"), []byte("www/*.log\n"), 0o644))
			must(t, os.WriteFile(filepath.Join(src, "www", "index.html"), []byte("hello-context\n"), 0o644))
			must(t, os.WriteFile(filepath.Join(src, "www", "debug.log"), []byte("ignored\n"), 0o644))
			if err := os.Symlink("index.html", filepath.Join(src, "www", "alias.html")); err != nil {
				t.Skipf("symlinks unavailable here: %v", err)
			}
			c, err := contract.Parse([]byte(fmt.Sprintf(`apiVersion: vulnsuite/v1
kind: Target
metadata: { id: e2e-context-%s, summary: e2e build context symlinks and dockerignore }
base: { kind: build, context: src }
service:
  ports: [ { container: 8080, protocol: tcp } ]
  command: [httpd, -f, -p, "8080", -h, /www]
  healthcheck: { tcp: { port: 8080 }, timeout: 30s }
states:
  vulnerable:
    verify:
      - exec: { run: "readlink /www/alias.html; cat /www/alias.html; test -e /www/debug.log && echo LEAKED || echo absent", stdout_matches: "^index\\.html\\s+hello-context\\s+absent\\s*$" }
`, kind)))
			if err != nil {
				t.Fatal(err)
			}
			c.Folder = dir
			t.Cleanup(func() { _ = eng.ImageRemove(context.Background(), c.ImageTag("vulnerable"), true) })
			h := runHost(t, ctx, runner.New(eng), c, runner.Options{Verify: true, Build: builder.Options{Pull: true}})
			t.Logf("%s", h.VerifyDetail)
		})
	}
}
