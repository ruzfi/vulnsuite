package e2e

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/engines"
)

// TestPauseAndArchive checks both engines' optional Pauser and FileReader
// against the daemon (#98): exec is refused while a container is paused, the
// archive API reads it while paused, and a paused container can be removed.
func TestPauseAndArchive(t *testing.T) {
	if os.Getenv("VULNSUITE_E2E") == "" {
		t.Skip("set VULNSUITE_E2E=1 to run against a Docker daemon")
	}
	const img = "busybox:latest"
	const setup = `mkdir -p /var/log/asan/sub && chmod 1777 /var/log/asan && echo hi > /var/log/asan/a &&
head -c 5000 /dev/zero > /var/log/asan/big && echo n > /var/log/asan/sub/n && ln -s /etc/passwd /var/log/asan/l &&
touch /tmp/ready && exec sleep 300`
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
			p, ok1 := eng.(engine.Pauser)
			r, ok2 := eng.(engine.FileReader)
			if !ok1 || !ok2 {
				t.Fatalf("%T implements Pauser %v, FileReader %v; want both", eng, ok1, ok2)
			}
			if ok, _ := eng.ImageExists(ctx, img, ""); !ok {
				if err := eng.ImagePull(ctx, img, "", nil); err != nil {
					t.Skipf("cannot pull %s: %v", img, err)
				}
				t.Cleanup(func() { _ = eng.ImageRemove(context.Background(), img, false) })
			}
			name := fmt.Sprintf("vulnsuite-e2e-pause-%s-%d-%d", kind, os.Getpid(), time.Now().UnixNano())
			id, err := eng.ContainerCreate(ctx, engine.ContainerSpec{Name: name, Image: img, Cmd: []string{"sh", "-c", setup},
				Labels: map[string]string{"dev.vulnsuite.managed": "true"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = eng.ContainerRemove(context.Background(), name) })
			if err := eng.ContainerStart(ctx, id); err != nil {
				t.Fatal(err)
			}
			for {
				_, err := r.ContainerStatPath(ctx, name, "/tmp/ready")
				if err == nil {
					break
				}
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("stat /tmp/ready: %v", err)
				}
				select {
				case <-ctx.Done():
					t.Fatal("the container never got ready")
				case <-time.After(50 * time.Millisecond):
				}
			}

			if err := p.ContainerPause(ctx, name); err != nil {
				t.Fatal(err)
			}
			_, _, err = eng.ContainerExec(ctx, name, "true", 10*time.Second)
			t.Logf("exec while paused: %v", err)
			if err == nil || !strings.Contains(err.Error(), "is paused") {
				t.Errorf("exec while paused = %v; want the daemon's refusal", err)
			}
			err = p.ContainerPause(ctx, name)
			t.Logf("pause while paused: %v", err)
			if err == nil || !strings.Contains(err.Error(), "already paused") {
				t.Errorf("pause while paused = %v; want an error", err)
			}
			if err := eng.ContainerStart(ctx, name); err == nil {
				t.Error("start while paused succeeded")
			}
			if rows, err := eng.ContainerList(ctx, false, name); err != nil || len(rows) != 1 || rows[0].State != "paused" {
				t.Errorf("a paused container lists as %+v, %v", rows, err)
			}
			// The archive API reads a paused container.
			if mode, err := r.ContainerStatPath(ctx, name, "/var/log/asan"); err != nil || mode != fs.ModeDir|fs.ModeSticky|0o777 {
				t.Errorf("stat /var/log/asan = %v, %v; want dtrwxrwxrwx", mode, err)
			}
			if mode, err := r.ContainerStatPath(ctx, name, "/var/log/asan/l"); err != nil || mode&fs.ModeSymlink == 0 {
				t.Errorf("stat of a symlink = %v, %v; want the link itself", mode, err)
			}
			if _, err := r.ContainerStatPath(ctx, name, "/var/log/missing"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("stat of a missing path = %v; want fs.ErrNotExist", err)
			}
			if _, err := r.ContainerStatPath(ctx, name+"-missing", "/"); err == nil || errors.Is(err, fs.ErrNotExist) {
				t.Errorf("stat in a missing container = %v; want an error that is not fs.ErrNotExist", err)
			}
			files, err := r.ContainerReadDir(ctx, name, "/var/log/asan", 1024)
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 2 || string(files["a"].Data) != "hi\n" || files["big"].Size != 5000 || len(files["big"].Data) != 1024 {
				t.Errorf("ReadDir = %d files (%v); want a and big (5000 bytes cut to 1024), no sub or symlink", len(files), files)
			}
			if _, err := r.ContainerReadDir(ctx, name, "/var/log/missing", 1); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("ReadDir of a missing dir = %v; want fs.ErrNotExist", err)
			}
			if _, err := r.ContainerReadDir(ctx, name, "/var/log/asan/a", 1); err == nil {
				t.Error("ReadDir of a file succeeded")
			}

			if err := p.ContainerUnpause(ctx, name); err != nil {
				t.Fatal(err)
			}
			if code, out, err := eng.ContainerExec(ctx, name, "echo ok", 10*time.Second); err != nil || code != 0 || out != "ok\n" {
				t.Errorf("exec after unpause = %d, %q, %v", code, out, err)
			}
			err = p.ContainerUnpause(ctx, name)
			t.Logf("unpause while running: %v", err)
			if err == nil || !strings.Contains(err.Error(), "not paused") {
				t.Errorf("unpause while running = %v; want an error", err)
			}

			// A paused container is removed (forced), so a crashed run cannot
			// strand one.
			if err := p.ContainerPause(ctx, name); err != nil {
				t.Fatal(err)
			}
			if err := eng.ContainerRemove(ctx, name); err != nil {
				t.Fatalf("removing a paused container: %v", err)
			}
			if _, err := eng.ContainerInspect(ctx, name); err == nil {
				t.Error("the removed paused container still inspects")
			}
			if err := p.ContainerPause(ctx, name); err == nil {
				t.Error("pausing a missing container succeeded")
			}
		})
	}
}
