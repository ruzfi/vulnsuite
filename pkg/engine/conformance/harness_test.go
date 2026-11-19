package conformance

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/docker"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/engine/moby"
)

// Backend names, as used in known-divergence tables.
const (
	sdk  = "moby" // engine/moby, the default (-engine sdk)
	api  = "api"  // engine/docker, the built-in client (-engine api)
	fake = "fake" // enginetest.Fake
)

// harness is one engine under test plus the world behind it: the shared daemon
// stub for the real clients, the fake's own state for the fake. Cases arrange
// the world through it so that one case body runs against all three.
type harness struct {
	name string
	eng  engine.Engine
	d    *daemon          // nil for the fake
	f    *enginetest.Fake // nil for the real clients
}

type backend struct {
	name string
	new  func(t *testing.T) *harness
}

var backends = []backend{
	{sdk, func(t *testing.T) *harness {
		d := newDaemon(t)
		e, err := moby.New(d.host())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Client().Close() })
		return &harness{name: sdk, eng: e, d: d}
	}},
	{api, func(t *testing.T) *harness {
		d := newDaemon(t)
		c, err := docker.New(d.host())
		if err != nil {
			t.Fatal(err)
		}
		return &harness{name: api, eng: c, d: d}
	}},
	{fake, func(*testing.T) *harness {
		// The fake's world and engine are the same object.
		f := enginetest.New()
		return &harness{name: fake, eng: f, f: f}
	}},
}

// divergence skips the case for this backend when it is listed in known, a
// map of backend -> why (naming the pull request that fixes it).
func (h *harness) divergence(t *testing.T, known map[string]string) {
	t.Helper()
	if why, ok := known[h.name]; ok {
		t.Skipf("known divergence (%s): %s", h.name, why)
	}
}

// needsDaemon skips the case for the fake: it injects a daemon-side failure
// the fake has no equivalent for.
func (h *harness) needsDaemon(t *testing.T) {
	t.Helper()
	if h.d == nil {
		t.Skip("not applicable: injects a daemon response the fake has no equivalent for")
	}
}

// fail makes daemon requests matching method and path (a regexp over the
// versionless path, e.g. `^/images/.+/json$`) fail with status and msg.
func (h *harness) fail(t *testing.T, method, path string, status int, msg string) *fault {
	t.Helper()
	h.needsDaemon(t)
	f := &fault{method: method, path: regexp.MustCompile(path), status: status, msg: msg}
	h.d.fail(f)
	return f
}

func (h *harness) seedImage(ref, platform string) {
	if h.f != nil {
		h.f.Images[ref] = true
		if platform != "" {
			h.f.ImagePlatforms[ref] = platform
		}
		return
	}
	h.d.addImage(ref, platform)
}

// seedNetwork creates a network out of band (as an earlier run would have)
// and returns its id.
func (h *harness) seedNetwork(spec engine.NetworkSpec) string {
	if h.f != nil {
		h.f.Networks[spec.Name] = spec
		return "net-" + spec.Name
	}
	return h.d.addNetwork(spec)
}

// network returns the daemon's (or the fake's) record of a network.
func (h *harness) network(name string) (engine.NetworkSpec, bool) {
	if h.f != nil {
		spec, found := h.f.Networks[name]
		return spec, found
	}
	spec, _, ok := h.d.network(name)
	return spec, ok
}

// exit makes a container's process exit with code.
func (h *harness) exit(name string, code int) {
	if h.f != nil {
		h.f.Exit(name, code)
		return
	}
	h.d.exit(name, code)
}

// onExec answers ContainerExec: fn receives the container (as named by the
// caller) and the shell command.
func (h *harness) onExec(t *testing.T, fn func(container, command string) (int, string)) {
	if h.f != nil {
		h.f.ExecFn = func(c, cmd string) (int, string, error) {
			code, out := fn(c, cmd)
			return code, out, nil
		}
		return
	}
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	h.d.execFn = func(c string, cmd []string) (int, string) {
		// Both clients run the command through sh -c.
		if len(cmd) != 3 || cmd[0] != "sh" || cmd[1] != "-c" {
			t.Errorf("exec Cmd = %q, want [sh -c <command>]", cmd)
			return -1, ""
		}
		return fn(c, cmd[2])
	}
}

func (h *harness) setLogs(text string) {
	if h.f != nil {
		h.f.LogsFn = func(engine.ContainerSpec) string { return text }
		return
	}
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	h.d.logs = text
}

// failPull makes pulling ref fail with msg (reported in the progress stream).
func (h *harness) failPull(ref, msg string) {
	if h.f != nil {
		h.f.PullFn = func(r string) error {
			if r == ref {
				return fmt.Errorf("%s", msg)
			}
			return nil
		}
		return
	}
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	h.d.pullErr[ref] = msg
}

// failPush makes pushing ref fail with msg, reported in the progress stream
// (daemon only: the fake has no push failure hook).
func (h *harness) failPush(t *testing.T, ref, msg string) {
	t.Helper()
	h.needsDaemon(t)
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	h.d.pushErr[ref] = msg
}

// streamErrorForm makes the daemon report progress-stream failures in only
// one form, "error" or "errorDetail" (dockerd sends both).
func (h *harness) streamErrorForm(t *testing.T, form string) {
	t.Helper()
	h.needsDaemon(t)
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	h.d.errForm = form
}

// failBuild makes every build fail with msg (reported in the build stream,
// after some step output).
func (h *harness) failBuild(msg string) {
	if h.f != nil {
		h.f.FailBuild = msg
		return
	}
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	h.d.buildErr = msg
}

func (h *harness) lastBuild(t *testing.T) buildRecord {
	t.Helper()
	if h.f != nil {
		if len(h.f.Builds) == 0 {
			t.Fatal("no build recorded")
		}
		b := h.f.Builds[len(h.f.Builds)-1]
		return buildRecord{Tags: b.Tags, Dockerfile: b.Dockerfile, BuildArgs: b.BuildArgs, Labels: b.Labels, NoCache: b.NoCache, Platform: b.Platform, Files: b.Files}
	}
	b, ok := h.d.lastBuild()
	if !ok {
		t.Fatal("no build recorded")
	}
	return b
}

// created returns the entrypoint and command container name was created with,
// as the daemon received them.
func (h *harness) created(t *testing.T, name string) (entrypoint, cmd []string) {
	t.Helper()
	if h.f != nil {
		c, ok := h.f.Containers[name]
		if !ok {
			t.Fatalf("no container %s", name)
		}
		return c.Spec.Entrypoint, c.Spec.Cmd
	}
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	c := h.d.container(name)
	if c == nil {
		t.Fatalf("no container %s", name)
	}
	return c.entrypoint, c.cmd
}

// failRemove makes removing container name fail with msg.
func (h *harness) failContainerRemove(t *testing.T, name, msg string) {
	if h.f != nil {
		h.f.RemoveFn = func(n string) error {
			if n == name {
				return fmt.Errorf("%s", msg)
			}
			return nil
		}
		return
	}
	h.fail(t, "DELETE", `^/containers/`+regexp.QuoteMeta(name)+`$`, 500, msg)
}

// failImageRemove makes removing image ref fail with msg (e.g. in use).
func (h *harness) failImageRemove(t *testing.T, ref, msg string) {
	if h.f != nil {
		h.f.ImageRemoveFn = func(r string) error {
			if r == ref {
				return fmt.Errorf("%s", msg)
			}
			return nil
		}
		return
	}
	h.fail(t, "DELETE", `^/images/`+regexp.QuoteMeta(ref)+`$`, 409, msg)
}

func contains(err error, sub string) bool { return err != nil && strings.Contains(err.Error(), sub) }
