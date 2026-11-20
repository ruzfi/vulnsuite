package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/probes"
	"github.com/ruzfi/vulnsuite/pkg/runner"
	"github.com/ruzfi/vulnsuite/pkg/validator"
)

// uafSource is a single-threaded TCP server built with ASan. "arm" allocates
// a session; "fire" frees it and, unless built with -DPATCHED, reads it
// afterwards: a heap-use-after-free in handle_fire that ASan reports to
// log_path and then aborts on (halt_on_error=1).
const uafSource = `#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct session { char name[32]; int armed; };
static struct session *cur;

static void reply(int fd, const char *s) { if (write(fd, s, strlen(s)) < 0) { /* the client left */ } }

__attribute__((noinline)) static void handle_arm(int fd) {
	if (!cur)
		cur = calloc(1, sizeof *cur);
	strcpy(cur->name, "client");
	cur->armed = 1;
	reply(fd, "armed\n");
}

__attribute__((noinline)) static void handle_fire(int fd) {
	struct session *s = cur;
	if (!s) {
		reply(fd, "not armed\n");
		return;
	}
	free(s); /* the client went away: release its session */
#ifdef PATCHED
	cur = NULL;
	fprintf(stderr, "fire: session released safely\n");
#else
	fprintf(stderr, "fire: session %s armed=%d\n", s->name, s->armed);
#endif
	reply(fd, "fired\n");
}

int main(void) {
	signal(SIGPIPE, SIG_IGN);
	setvbuf(stderr, NULL, _IONBF, 0);
	int one = 1, ls = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(7000) };
	setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0 || listen(ls, 16) < 0) {
		perror("listen");
		return 1;
	}
	fprintf(stderr, "listening on 7000\n");
	for (;;) {
		int fd = accept(ls, NULL, NULL);
		if (fd < 0)
			continue;
		char buf[64] = {0};
		if (read(fd, buf, sizeof buf - 1) > 0) {
			if (!strncmp(buf, "arm", 3))
				handle_arm(fd);
			else if (!strncmp(buf, "fire", 4))
				handle_fire(fd);
			else
				reply(fd, "?\n");
		}
		close(fd);
	}
}
`

const uafDockerfile = `FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY uaf.c /src/uaf.c
RUN gcc -g -O1 -fno-omit-frame-pointer -fsanitize=address -o /usr/local/bin/uaf-vulnerable /src/uaf.c \
 && gcc -g -O1 -fno-omit-frame-pointer -fsanitize=address -DPATCHED -o /usr/local/bin/uaf-patched /src/uaf.c \
 && mkdir -p /var/log/asan && chmod 1777 /var/log/asan
EXPOSE 7000
CMD ["/usr/local/bin/uaf-vulnerable"]
`

// sequenceContract drives the server from a busybox sidecar: arm, freeze the
// target, fire (queued in the frozen server's socket), resume, and read the
// ASan report. The server runs as nobody, so the report is written only
// because log_dir is 1777. Vulnerable needs two hits, so the target (aborted
// by ASan) is restarted between attempts.
const sequenceContract = `apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: ID
  summary: e2e fixture for the sequence verify kind (#98)
  vuln_refs: [VS-E2E-SEQUENCE]
  severity: low
  references: [https://example.invalid]
  detection: custom-only
base: { kind: build, context: build, dockerfile: Dockerfile }
service:
  ports: [ { container: 7000, protocol: tcp } ]
  command: [/usr/local/bin/uaf-vulnerable]
  user: "65534"
  environment: { ASAN_OPTIONS: "detect_leaks=0:halt_on_error=1:abort_on_error=0:log_path=/var/log/asan/asan" }
  healthcheck: { tcp: { port: 7000 }, timeout: 30s }
  sanitizer: { log_dir: /var/log/asan }
  sidecars:
    - { name: driver, image: busybox:1.36.1, digest: "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662", command: [sleep, "3600"] }
states:
  vulnerable:
    verify:
      - sequence:
          attempts: 2
          min_hits: 2
          timeout: 60
          steps:
            - exec: { container: driver, run: "printf 'arm\\n' | nc -w 2 ID 7000", stdout_matches: armed, timeout: 10 }
            - freeze: {}
            - exec: { container: driver, run: "printf 'fire\\n' | nc -w 1 ID 7000; true", timeout: 10 }
            - sleep: { ms: 100 }
            - resume: {}
            - expect_sanitizer: { kind: heap-use-after-free, frame: "^handle_fire " }
  patched:
    command: [/usr/local/bin/uaf-patched]
    verify:
      - sequence:
          attempts: 2
          steps:
            - exec: { container: driver, run: "printf 'arm\\n' | nc -w 2 ID 7000", stdout_matches: armed, timeout: 10 }
            - freeze: {}
            - exec: { container: driver, run: "printf 'fire\\n' | nc -w 1 ID 7000; true", timeout: 10 }
            - sleep: { ms: 100 }
            - resume: {}
            - expect_sanitizer: none
            - expect_log: "session released safely"
`

// TestSequenceVerify runs the sequence executor against the daemon (#98):
// vulnerable hits twice (restarted in between), in internal and host mode;
// patched passes with its positive control; a paused target is stopped.
func TestSequenceVerify(t *testing.T) {
	if os.Getenv("VULNSUITE_E2E") == "" {
		t.Skip("set VULNSUITE_E2E=1 to run against a Docker daemon")
	}
	for _, kind := range []string{"sdk", "api"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			eng := daemon(t, ctx, kind)
			// Unique per run: two e2e runs sharing a daemon must not touch
			// each other's containers or network.
			id := fmt.Sprintf("e2e-sequence-%s-%d", kind, os.Getpid())
			netName := fmt.Sprintf("vulnsuite-e2e-seq-%s-%d", kind, os.Getpid())

			dir := t.TempDir()
			must(t, os.MkdirAll(filepath.Join(dir, "build"), 0o755))
			must(t, os.WriteFile(filepath.Join(dir, "build", "Dockerfile"), []byte(uafDockerfile), 0o644))
			must(t, os.WriteFile(filepath.Join(dir, "build", "uaf.c"), []byte(uafSource), 0o644))
			c, err := contract.Parse([]byte(strings.ReplaceAll(sequenceContract, "ID", id)))
			if err != nil {
				t.Fatal(err)
			}
			c.Folder = dir
			for _, f := range (&validator.Validator{}).Check(c) {
				if f.Level == validator.Error {
					t.Fatalf("the fixture does not validate: %s", f)
				}
				t.Logf("validate: %s", f)
			}

			r := runner.New(eng)
			t.Cleanup(func() {
				cctx := context.Background()
				if _, err := r.StopAll(cctx, id); err != nil {
					t.Errorf("cleanup: %v", err)
				}
				_ = r.PruneNetwork(cctx, netName)
				for _, state := range []string{"vulnerable", "patched"} {
					_ = eng.ImageRemove(cctx, c.ImageTag(state), true)
				}
			})
			run := func(state string, exp runner.Exposure) *runner.Handle {
				t.Helper()
				start := time.Now()
				h, err := r.Run(ctx, c, state, exp, runner.Options{Verify: true, Build: builder.Options{}})
				if err != nil {
					t.Fatalf("%s %s: %v", state, exp.Mode, err)
				}
				t.Logf("%s, %s mode, %v:\n%s", state, exp.Mode, time.Since(start).Round(time.Millisecond), h.VerifyDetail)
				if !h.Ready || h.VerifyOK == nil || !*h.VerifyOK {
					t.Fatalf("%s %s: ready=%v verify=%v:\n%s", state, exp.Mode, h.Ready, h.VerifyOK, h.VerifyDetail)
				}
				return h
			}
			internal := runner.Exposure{Mode: runner.ModeInternal, Network: netName}

			// Vulnerable: both attempts hit; ASan aborted the server after
			// the first, so the second ran on a restarted target.
			for _, exp := range []runner.Exposure{internal, {Mode: runner.ModeHost, Bind: "127.0.0.1"}} {
				h := run("vulnerable", exp)
				a := h.Probes[0].Attempts
				if len(a) != 2 || a[0].Outcome != probes.OutcomeHit || a[1].Outcome != probes.OutcomeHit || !a[1].Restarted {
					t.Fatalf("vulnerable %s attempts %+v", exp.Mode, a)
				}
				if !strings.Contains(a[0].Detail, "heap-use-after-free at handle_fire uaf.c:") {
					t.Fatalf("hit detail %q", a[0].Detail)
				}
				if err := r.Stop(ctx, h); err != nil {
					t.Fatal(err)
				}
			}

			// Patched: no report, and the log shows the race path ran.
			h := run("patched", internal)
			if a := h.Probes[0].Attempts; len(a) != 1 || a[0].Outcome != probes.OutcomePass ||
				!strings.HasSuffix(a[0].Detail, `-> ok; no sanitizer report; log ~ /session released safely/`) {
				t.Fatalf("patched attempts %+v", a)
			}

			// A paused target is stopped without an unpause first.
			if err := eng.(engine.Pauser).ContainerPause(ctx, h.Container); err != nil {
				t.Fatal(err)
			}
			if err := r.Stop(ctx, h); err != nil {
				t.Fatalf("stop a paused target: %v", err)
			}
			if _, err := eng.ContainerInspect(ctx, h.Container); err == nil {
				t.Fatal("the paused target is still there after stop")
			}
		})
	}
}
