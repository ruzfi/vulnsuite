package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/engines"
)

// TestExecContract checks both engines honour the exec timeout and report the
// real exit code of a command that writes more than the 1 MiB output cap
// (#40 items 2 and 3).
func TestExecContract(t *testing.T) {
	if os.Getenv("VULNSUITE_E2E") == "" {
		t.Skip("set VULNSUITE_E2E=1 to run against a Docker daemon")
	}
	const img = "busybox:latest"
	for _, kind := range []string{"sdk", "api"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			eng, err := engines.New(kind, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := eng.Ping(ctx); err != nil {
				t.Skipf("no daemon: %v", err)
			}
			if ok, _ := eng.ImageExists(ctx, img); !ok {
				if err := eng.ImagePull(ctx, img, nil); err != nil {
					t.Skipf("cannot pull %s: %v", img, err)
				}
				t.Cleanup(func() { _ = eng.ImageRemove(context.Background(), img, false) })
			}
			name := "vulnsuite-e2e-exec-" + kind
			_ = eng.ContainerRemove(ctx, name)
			id, err := eng.ContainerCreate(ctx, engine.ContainerSpec{Name: name, Image: img, Cmd: []string{"sleep", "300"},
				Labels: map[string]string{"dev.vulnsuite.managed": "true"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = eng.ContainerRemove(context.Background(), name) })
			if err := eng.ContainerStart(ctx, id); err != nil {
				t.Fatal(err)
			}

			start := time.Now()
			_, _, err = eng.ContainerExec(ctx, name, "sleep 8", time.Second)
			if el := time.Since(start); el > 4*time.Second {
				t.Fatalf("exec timeout ignored: returned after %v", el)
			}
			if err == nil {
				t.Fatal("a timed-out exec must return an error")
			}

			code, out, err := eng.ContainerExec(ctx, name, "head -c 1100000 /dev/zero; sleep 2; exit 7", 30*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if code != 7 {
				t.Fatalf("exit code %d after >1 MiB of output, want 7", code)
			}
			if len(out) != 1<<20 {
				t.Fatalf("output %d bytes, want capped at 1 MiB", len(out))
			}
		})
	}
}
