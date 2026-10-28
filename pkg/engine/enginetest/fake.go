// Package enginetest provides an in-memory engine.Engine for tests.
package enginetest

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// Build records one ImageBuild call.
type Build struct {
	Tags       []string
	Dockerfile string
	BuildArgs  map[string]string
	Labels     map[string]string
	NoCache    bool
	// Files holds the tar context, path -> content.
	Files map[string]string
}

// Container records a created container.
type Container struct {
	ID      string
	Spec    engine.ContainerSpec
	Running bool
	IP      string
}

// Fake is an in-memory engine.
type Fake struct {
	mu         sync.Mutex
	Images     map[string]bool
	Builds     []Build
	Pulls      []string
	Pushes     []string
	Tagged     [][2]string
	Containers map[string]*Container
	Networks   map[string]engine.NetworkSpec
	Execs      []string
	// ExecFn answers ContainerExec when set.
	ExecFn func(container, command string) (int, string, error)
	// LogsFn answers ContainerLogs when set (receives the container spec).
	LogsFn func(spec engine.ContainerSpec) string
	// FailBuild makes every build fail with this message when set.
	FailBuild string
	// FailPull makes pulls fail.
	FailPull bool
	nextIP   int
	nextID   int
	// HostInfo is what Info reports (default linux/amd64).
	HostInfo engine.HostInfo
	// HostAddr is the daemon address Host() reports (empty = local socket).
	HostAddr string
}

// Host returns the configured daemon address, mirroring the real engines so the
// runner can tell a remote daemon from a local one.
func (f *Fake) Host() string { return f.HostAddr }

// New returns an empty fake.
func New() *Fake {
	return &Fake{Images: map[string]bool{}, Containers: map[string]*Container{}, Networks: map[string]engine.NetworkSpec{},
		HostInfo: engine.HostInfo{OS: "linux", Arch: "amd64"}}
}

func (f *Fake) Ping(context.Context) (string, error) { return "fake", nil }

func (f *Fake) Info(context.Context) (engine.HostInfo, error) { return f.HostInfo, nil }

func (f *Fake) ImageExists(_ context.Context, ref string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Images[ref], nil
}

func (f *Fake) ImagePull(_ context.Context, ref string, out io.Writer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailPull {
		return fmt.Errorf("pull %s: fake registry down", ref)
	}
	f.Pulls = append(f.Pulls, ref)
	f.Images[ref] = true
	if out != nil {
		fmt.Fprintf(out, "pulled %s\n", ref)
	}
	return nil
}

func (f *Fake) ImageBuild(_ context.Context, opts engine.BuildOptions, out io.Writer) error {
	files := map[string]string{}
	tr := tar.NewReader(opts.Context)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = string(b)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Builds = append(f.Builds, Build{Tags: opts.Tags, Dockerfile: opts.Dockerfile, BuildArgs: opts.BuildArgs, Labels: opts.Labels, NoCache: opts.NoCache, Files: files})
	if f.FailBuild != "" {
		if out != nil {
			fmt.Fprintln(out, "Step 1/1 : FROM x")
		}
		return fmt.Errorf("%s", f.FailBuild)
	}
	for _, t := range opts.Tags {
		f.Images[t] = true
	}
	if out != nil {
		fmt.Fprintf(out, "Successfully tagged %s\n", strings.Join(opts.Tags, ","))
	}
	return nil
}

func (f *Fake) ImageTag(_ context.Context, source, target string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.Images[source] {
		return fmt.Errorf("no such image %s", source)
	}
	f.Images[target] = true
	f.Tagged = append(f.Tagged, [2]string{source, target})
	return nil
}

func (f *Fake) ImagePush(_ context.Context, ref string, out io.Writer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.Images[ref] {
		return fmt.Errorf("no such image %s", ref)
	}
	f.Pushes = append(f.Pushes, ref)
	return nil
}

func (f *Fake) ImageRemove(_ context.Context, ref string, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.Images, ref)
	return nil
}

func (f *Fake) ImageList(_ context.Context, prefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for ref := range f.Images {
		if strings.HasPrefix(ref, prefix) {
			out = append(out, ref)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *Fake) ContainerCreate(_ context.Context, spec engine.ContainerSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.Images[spec.Image] {
		return "", fmt.Errorf("no such image: %s", spec.Image)
	}
	if _, dup := f.Containers[spec.Name]; dup {
		return "", fmt.Errorf("conflict: name %s already in use", spec.Name)
	}
	f.nextID++
	f.nextIP++
	c := &Container{ID: fmt.Sprintf("c%03d", f.nextID), Spec: spec, IP: fmt.Sprintf("172.30.0.%d", f.nextIP+1)}
	f.Containers[spec.Name] = c
	return c.ID, nil
}

func (f *Fake) byIDOrName(id string) *Container {
	if c, ok := f.Containers[id]; ok {
		return c
	}
	for _, c := range f.Containers {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (f *Fake) ContainerStart(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.byIDOrName(id)
	if c == nil {
		return fmt.Errorf("no such container %s", id)
	}
	c.Running = true
	return nil
}

func (f *Fake) ContainerRemove(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.byIDOrName(id)
	if c != nil {
		delete(f.Containers, c.Spec.Name)
	}
	return nil
}

func (f *Fake) ContainerList(_ context.Context, all bool, prefix string) ([]engine.ContainerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []engine.ContainerInfo
	for name, c := range f.Containers {
		if !strings.HasPrefix(name, prefix) || (!all && !c.Running) {
			continue
		}
		st := "exited"
		if c.Running {
			st = "running"
		}
		out = append(out, engine.ContainerInfo{ID: c.ID, Name: name, Image: c.Spec.Image, State: st, Status: "Up", Labels: c.Spec.Labels})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *Fake) ContainerInspect(_ context.Context, id string) (*engine.ContainerDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.byIDOrName(id)
	if c == nil {
		return nil, fmt.Errorf("no such container %s", id)
	}
	d := &engine.ContainerDetail{ID: c.ID, Name: c.Spec.Name, Image: c.Spec.Image, Running: c.Running, IPs: map[string]string{}, Ports: map[string]engine.HostBinding{}}
	if c.Spec.Network != nil {
		d.IPs[c.Spec.Network.Name] = c.IP
	}
	for _, p := range c.Spec.Ports {
		d.Ports[fmt.Sprintf("%d/tcp", p.ContainerPort)] = engine.HostBinding{IP: p.HostIP, Port: p.HostPort}
	}
	return d, nil
}

func (f *Fake) ContainerExec(_ context.Context, id, command string, _ time.Duration) (int, string, error) {
	f.mu.Lock()
	f.Execs = append(f.Execs, id+": "+command)
	fn := f.ExecFn
	f.mu.Unlock()
	if fn != nil {
		return fn(id, command)
	}
	return 0, "", nil
}

func (f *Fake) ContainerLogs(_ context.Context, id string, _ int) (string, error) {
	f.mu.Lock()
	c := f.byIDOrName(id)
	fn := f.LogsFn
	f.mu.Unlock()
	if c == nil {
		return "", fmt.Errorf("no such container %s", id)
	}
	if fn != nil {
		return fn(c.Spec), nil
	}
	return "", nil
}
func (f *Fake) ContainerWait(context.Context, string) (int, error) { return 0, nil }

func (f *Fake) NetworkEnsure(_ context.Context, spec engine.NetworkSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Networks[spec.Name] = spec
	return "net-" + spec.Name, nil
}

func (f *Fake) NetworkExists(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.Networks[name]
	return ok, nil
}

func (f *Fake) NetworkRemove(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.Networks, name)
	return nil
}

var _ engine.Engine = (*Fake)(nil)
