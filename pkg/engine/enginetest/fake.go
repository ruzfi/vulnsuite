// Package enginetest provides an in-memory engine.Engine for tests.
package enginetest

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"net"
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
	Platform   string
	// Files holds the tar context, path -> content.
	Files map[string]string
	// Modes holds the tar context's file modes, path -> mode.
	Modes map[string]int64
}

// Container records a created container.
type Container struct {
	ID      string
	Spec    engine.ContainerSpec
	Running bool
	// ExitCode is reported by ContainerInspect once the container has exited
	// (see Exit).
	ExitCode int
	IP       string
	// Networks are further networks attached with NetworkConnect.
	Networks []engine.NetworkAttachment
}

// Fake is an in-memory engine.
type Fake struct {
	mu     sync.Mutex
	Images map[string]bool
	// ImagePlatforms records the platform an image was pulled or built for
	// ("" or absent = engine default, which satisfies any platform).
	ImagePlatforms map[string]string
	Builds         []Build
	Pulls          []string
	Pushes         []string
	Tagged         [][2]string
	Containers     map[string]*Container
	Networks       map[string]engine.NetworkSpec
	Execs          []string
	// ExecFn answers ContainerExec when set.
	ExecFn func(container, command string) (int, string, error)
	// LogsFn answers ContainerLogs when set (receives the container spec).
	LogsFn func(spec engine.ContainerSpec) string
	// StartFn runs when a container starts (receives its spec), e.g. to stand
	// up a listener on a published host port. An error fails the start.
	StartFn func(spec engine.ContainerSpec) error
	// RemoveFn runs before a container is removed (receives its name); an error
	// fails the removal and leaves the container in place.
	RemoveFn func(name string) error
	// ImageRemoveFn runs before an image is removed (receives its ref); an
	// error fails the removal and keeps the image.
	ImageRemoveFn func(ref string) error
	// NoAssignPorts leaves host port 0 bindings unassigned on start (a daemon
	// that does not report its assignment).
	NoAssignPorts bool
	// ListErr makes ContainerList fail when set.
	ListErr error
	// FailBuild makes every build fail with this message when set.
	FailBuild string
	// FailPull makes pulls fail.
	FailPull bool
	// PullFn runs before an image is pulled (receives its ref); an error fails
	// the pull.
	PullFn func(ref string) error
	nextIP int
	nextID int
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
	return &Fake{Images: map[string]bool{}, ImagePlatforms: map[string]string{}, Containers: map[string]*Container{}, Networks: map[string]engine.NetworkSpec{},
		HostInfo: engine.HostInfo{OS: "linux", Arch: "amd64"}}
}

func (f *Fake) Ping(context.Context) (string, error) { return "fake", nil }

func (f *Fake) Info(context.Context) (engine.HostInfo, error) { return f.HostInfo, nil }

func (f *Fake) ImageExists(_ context.Context, ref, platform string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Images[ref] && f.platformOK(ref, platform), nil
}

// platformOK reports whether the image ref satisfies platform.
func (f *Fake) platformOK(ref, platform string) bool {
	have := f.ImagePlatforms[ref]
	if platform == "" || have == "" {
		return true
	}
	hOS, hArch, hVariant := engine.SplitPlatform(have)
	return engine.PlatformMatches(platform, hOS, hArch, hVariant)
}

func (f *Fake) setPlatform(ref, platform string) {
	if f.ImagePlatforms == nil {
		f.ImagePlatforms = map[string]string{}
	}
	if platform == "" {
		delete(f.ImagePlatforms, ref)
	} else {
		f.ImagePlatforms[ref] = platform
	}
}

func (f *Fake) ImagePull(_ context.Context, ref, platform string, out io.Writer) error {
	if f.PullFn != nil {
		if err := f.PullFn(ref); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailPull {
		return fmt.Errorf("pull %s: fake registry down", ref)
	}
	f.Pulls = append(f.Pulls, ref)
	f.Images[ref] = true
	f.setPlatform(ref, platform)
	if out != nil {
		fmt.Fprintf(out, "pulled %s\n", ref)
	}
	return nil
}

func (f *Fake) ImageBuild(_ context.Context, opts engine.BuildOptions, out io.Writer) error {
	files := map[string]string{}
	modes := map[string]int64{}
	tr := tar.NewReader(opts.Context)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = string(b)
		modes[h.Name] = h.Mode
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Builds = append(f.Builds, Build{Tags: opts.Tags, Dockerfile: opts.Dockerfile, BuildArgs: opts.BuildArgs, Labels: opts.Labels, NoCache: opts.NoCache, Platform: opts.Platform, Files: files, Modes: modes})
	if f.FailBuild != "" {
		if out != nil {
			fmt.Fprintln(out, "Step 1/1 : FROM x")
		}
		return fmt.Errorf("%s", f.FailBuild)
	}
	for _, t := range opts.Tags {
		f.Images[t] = true
		f.setPlatform(t, opts.Platform)
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
	f.setPlatform(target, f.ImagePlatforms[source])
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
	if f.ImageRemoveFn != nil {
		if err := f.ImageRemoveFn(ref); err != nil {
			return err
		}
	}
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

func (f *Fake) ContainerCreate(ctx context.Context, spec engine.ContainerSpec) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.Images[spec.Image] {
		return "", fmt.Errorf("no such image: %s", spec.Image)
	}
	if !f.platformOK(spec.Image, spec.Platform) {
		return "", fmt.Errorf("image %s was found but does not match the specified platform %s", spec.Image, spec.Platform)
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

// freeHostPort returns a currently free TCP port on host (127.0.0.1 for "" or
// 0.0.0.0).
func freeHostPort(host string) (int, error) {
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
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

func (f *Fake) ContainerStart(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	c := f.byIDOrName(id)
	if c == nil {
		f.mu.Unlock()
		return fmt.Errorf("no such container %s", id)
	}
	c.Running = true
	// Like the daemon, assign a free host port to every binding that asks
	// for host port 0 (a real free port, so a StartFn can listen on it).
	if !f.NoAssignPorts {
		ports := append([]engine.PortBinding(nil), c.Spec.Ports...)
		for i := range ports {
			if ports[i].HostPort == 0 {
				p, err := freeHostPort(ports[i].HostIP)
				if err != nil {
					f.mu.Unlock()
					return err
				}
				ports[i].HostPort = p
			}
		}
		c.Spec.Ports = ports
	}
	spec, fn := c.Spec, f.StartFn
	f.mu.Unlock()
	if fn != nil {
		return fn(spec)
	}
	return nil
}

func (f *Fake) ContainerRemove(ctx context.Context, id string) error {
	// Like the real engines, a cancelled context fails the removal.
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	fn := f.RemoveFn
	f.mu.Unlock()
	if fn != nil {
		if err := fn(id); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.byIDOrName(id)
	if c != nil {
		delete(f.Containers, c.Spec.Name)
	}
	return nil
}

func (f *Fake) ContainerList(ctx context.Context, all bool, prefix string) ([]engine.ContainerInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ListErr != nil {
		return nil, f.ListErr
	}
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
	d := &engine.ContainerDetail{ID: c.ID, Name: c.Spec.Name, Image: c.Spec.Image, Running: c.Running, ExitCode: c.ExitCode, IPs: map[string]string{}, Ports: map[string]engine.HostBinding{}}
	if c.Spec.Network != nil {
		d.IPs[c.Spec.Network.Name] = c.IP
	}
	for i, n := range c.Networks {
		d.IPs[n.Name] = fmt.Sprintf("10.99.%d.%d", i, f.nextIP)
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

// Exit marks a container as exited with code, as if its process ended.
func (f *Fake) Exit(idOrName string, code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.byIDOrName(idOrName); c != nil {
		c.Running = false
		c.ExitCode = code
	}
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

func (f *Fake) NetworkEnsure(ctx context.Context, spec engine.NetworkSpec) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
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

func (f *Fake) NetworkRemove(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for cname, c := range f.Containers {
		if attachedTo(c, name) {
			return fmt.Errorf("network %s has active endpoints (%s)", name, cname)
		}
	}
	delete(f.Networks, name)
	return nil
}

// NetworkConnect attaches a container to a further network.
func (f *Fake) NetworkConnect(ctx context.Context, network, container string, aliases []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.Networks[network]; !ok {
		return fmt.Errorf("no such network %s", network)
	}
	c := f.byIDOrName(container)
	if c == nil {
		return fmt.Errorf("no such container %s", container)
	}
	if attachedTo(c, network) {
		return fmt.Errorf("container %s is already attached to %s", container, network)
	}
	c.Networks = append(c.Networks, engine.NetworkAttachment{Name: network, Aliases: aliases})
	return nil
}

func attachedTo(c *Container, network string) bool {
	if c.Spec.Network != nil && c.Spec.Network.Name == network {
		return true
	}
	for _, n := range c.Networks {
		if n.Name == network {
			return true
		}
	}
	return false
}

// Resolve answers a name lookup made from inside the container named from:
// the containers sharing one of its user-defined networks under that name (an
// alias or a container name), sorted. It models Docker's embedded DNS, which
// does not exist on the default bridge.
func (f *Fake) Resolve(from, name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	src := f.byIDOrName(from)
	if src == nil {
		return nil
	}
	nets := map[string]bool{}
	for _, n := range attachments(src) {
		if n.Name != "" && n.Name != "bridge" {
			nets[n.Name] = true
		}
	}
	var out []string
	for cname, c := range f.Containers {
		for _, n := range attachments(c) {
			if !nets[n.Name] {
				continue
			}
			if cname == name || has(n.Aliases, name) {
				out = append(out, cname)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func attachments(c *Container) []engine.NetworkAttachment {
	var out []engine.NetworkAttachment
	if c.Spec.Network != nil {
		out = append(out, *c.Spec.Network)
	}
	return append(out, c.Networks...)
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

var _ engine.Engine = (*Fake)(nil)
