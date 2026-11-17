package runner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

// A container that crashes on boot must not cost the whole ready timeout, and
// the not-ready detail carries its exit code and last log lines.
func TestAwaitReadyStopsWhenContainerExits(t *testing.T) {
	fe := enginetest.New() // nothing listens on the published port
	fe.StartFn = func(spec engine.ContainerSpec) error {
		go func() {
			time.Sleep(100 * time.Millisecond)
			fe.Exit(spec.Name, 3)
		}()
		return nil
	}
	fe.LogsFn = func(engine.ContainerSpec) string { return "booting\nfatal: bad config\n" }
	r := New(fe)
	r.ExitPoll = 50 * time.Millisecond
	r.Reach = func(string, int, time.Duration) probes.Reach { return probes.Refused }
	c := load(t, "redis-unauthenticated-access")
	start := time.Now()
	h, err := r.Run(context.Background(), c, "vulnerable", Exposure{Mode: ModeHost, Bind: "127.0.0.1"},
		Options{ReadyTimeout: time.Minute, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("awaitReady took %s for a container that exited at once", el)
	}
	if h.Ready {
		t.Fatal("an exited container must not be ready")
	}
	if h.ExitCode == nil || *h.ExitCode != 3 {
		t.Fatalf("exit code: %v", h.ExitCode)
	}
	if !strings.Contains(h.ReadyDetail, "exited with code 3") || !strings.Contains(h.ReadyDetail, "fatal: bad config") {
		t.Fatalf("ready detail: %q", h.ReadyDetail)
	}
	if p := h.Problem(); p != "not ready: container exited with code 3" {
		t.Fatalf("problem: %q", p)
	}
}

// A running target that never passes its healthcheck reports the timeout and
// its logs.
func TestAwaitReadyTimeoutDetail(t *testing.T) {
	fe := enginetest.New()
	fe.LogsFn = func(engine.ContainerSpec) string { return "still starting\n" }
	r := New(fe)
	r.Reach = func(string, int, time.Duration) probes.Reach { return probes.Refused }
	c := load(t, "redis-unauthenticated-access")
	h, err := r.Run(context.Background(), c, "vulnerable", Exposure{Mode: ModeHost, Bind: "127.0.0.1"},
		Options{ReadyTimeout: time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.Ready || h.ExitCode != nil {
		t.Fatalf("ready=%v exit=%v", h.Ready, h.ExitCode)
	}
	if !strings.Contains(h.ReadyDetail, "did not pass within 1s") || !strings.Contains(h.ReadyDetail, "still starting") {
		t.Fatalf("ready detail: %q", h.ReadyDetail)
	}
}
