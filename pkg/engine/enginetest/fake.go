// Package enginetest provides an in-memory engine.Engine for tests.
package enginetest

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/distribution/reference"

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
	// Links holds the tar context's symlinks, path -> link target.
	Links map[string]string
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
	// Paused is set between ContainerPause and ContainerUnpause.
	Paused bool
	// Files is the container's filesystem as ContainerStatPath and
	// ContainerReadDir see it, absolute path -> file (see WriteFile).
	Files map[string]File
	// started is set by the first ContainerStart: a container that never ran
	// lists as "created", one that ran and stopped as "exited".
	started bool
}

// File is one entry of a fake container's filesystem.
type File struct {
	// Mode holds the type and permission bits (fs.ModeDir|fs.ModeSticky|0o777
	// for a world-writable sticky directory, 0o644 for a regular file).
	Mode fs.FileMode
	// Data is a regular file's content, or a symlink's target.
	Data string
	// ModTime is when WriteFile last wrote it.
	ModTime time.Time
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
	// ExecTimeouts holds the timeout of each recorded exec, parallel to Execs.
	ExecTimeouts []time.Duration
	// Calls logs, in order, every successful ContainerPause ("pause <c>"),
	// ContainerExec ("exec <c>: <command>") and ContainerUnpause
	// ("unpause <c>"), with <c> the container as the caller named it, so a
	// test can assert what ran while a container was frozen.
	Calls []string
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

// Ping reports the fake's version. Like the real engines, it and every other
// call fail once their context is done, so a cancelled run never reads as
// "image missing" or "network absent".
func (f *Fake) Ping(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "fake", nil
}

func (f *Fake) Info(ctx context.Context) (engine.HostInfo, error) {
	if err := ctx.Err(); err != nil {
		return engine.HostInfo{}, err
	}
	return f.HostInfo, nil
}

func (f *Fake) ImageExists(ctx context.Context, ref, platform string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key, ok := f.image(ref)
	return ok && f.platformOK(key, platform), nil
}

// ImagePlatform implements engine.ImagePlatformer: the platform recorded for
// the image in ImagePlatforms, else the host's (HostInfo).
func (f *Fake) ImagePlatform(ctx context.Context, ref string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key, ok := f.image(ref)
	if !ok {
		//lint:ignore ST1005 dockerd's message, verbatim
		return "", fmt.Errorf("No such image: %s", ref)
	}
	if p := f.ImagePlatforms[key]; p != "" {
		return p, nil
	}
	return engine.JoinPlatform(f.HostInfo.OS, f.HostInfo.Arch, ""), nil
}

var _ engine.ImagePlatformer = (*Fake)(nil)

// normalizeRef is the name a daemon resolves an image reference to, so that
// "busybox", "busybox:latest" and "docker.io/library/busybox:latest" are one
// image. A reference that does not parse is returned unchanged.
func normalizeRef(ref string) string {
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return ref
	}
	return reference.TagNameOnly(named).String()
}

// image returns the Images key that ref names, matched like a daemon does
// (see normalizeRef): ref itself when recorded, else the first (sorted)
// recorded reference that names the same image. Called with f.mu held.
func (f *Fake) image(ref string) (string, bool) {
	if f.Images[ref] {
		return ref, true
	}
	want := normalizeRef(ref)
	keys := make([]string, 0, len(f.Images))
	for k, ok := range f.Images {
		if ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if normalizeRef(k) == want {
			return k, true
		}
	}
	return "", false
}

// dockerfileIn reports whether the build context files hold the Dockerfile a
// build asks for (name, "Dockerfile" when empty). Like the legacy builder,
// the default name also matches a lower-case "dockerfile".
func dockerfileIn(files map[string]string, name string) bool {
	clean := func(p string) string { return strings.TrimPrefix(path.Clean("/"+p), "/") }
	want := []string{clean(name)}
	if name == "" {
		want = []string{"Dockerfile", "dockerfile"}
	}
	for f := range files {
		for _, w := range want {
			if clean(f) == w {
				return true
			}
		}
	}
	return false
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

func (f *Fake) ImagePull(ctx context.Context, ref, platform string, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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

func (f *Fake) ImageBuild(ctx context.Context, opts engine.BuildOptions, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	files := map[string]string{}
	modes := map[string]int64{}
	links := map[string]string{}
	tr := tar.NewReader(opts.Context)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Typeflag == tar.TypeSymlink {
			links[h.Name] = h.Linkname
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = string(b)
		modes[h.Name] = h.Mode
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Builds = append(f.Builds, Build{Tags: opts.Tags, Dockerfile: opts.Dockerfile, BuildArgs: opts.BuildArgs, Labels: opts.Labels, NoCache: opts.NoCache, Platform: opts.Platform, Files: files, Modes: modes, Links: links})
	if !dockerfileIn(files, opts.Dockerfile) {
		// The daemon's error when the context lacks the Dockerfile.
		name := opts.Dockerfile
		if name == "" {
			name = "Dockerfile"
		}
		//lint:ignore ST1005 dockerd's message, verbatim
		return fmt.Errorf("Cannot locate specified Dockerfile: %s", name)
	}
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

func (f *Fake) ImageTag(ctx context.Context, source, target string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key, ok := f.image(source)
	if !ok {
		return fmt.Errorf("no such image %s", source)
	}
	f.Images[target] = true
	f.setPlatform(target, f.ImagePlatforms[key])
	f.Tagged = append(f.Tagged, [2]string{source, target})
	return nil
}

func (f *Fake) ImagePush(ctx context.Context, ref string, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.image(ref); !ok {
		return fmt.Errorf("no such image %s", ref)
	}
	f.Pushes = append(f.Pushes, ref)
	return nil
}

func (f *Fake) ImageRemove(ctx context.Context, ref string, _ bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.ImageRemoveFn != nil {
		if err := f.ImageRemoveFn(ref); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Remove ref under every spelling it was recorded as.
	for key, ok := f.image(ref); ok; key, ok = f.image(ref) {
		delete(f.Images, key)
		delete(f.ImagePlatforms, key)
	}
	delete(f.Images, ref)
	return nil
}

func (f *Fake) ImageList(ctx context.Context, prefix string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	key, ok := f.image(spec.Image)
	if !ok {
		return "", fmt.Errorf("no such image: %s", spec.Image)
	}
	if !f.platformOK(key, spec.Platform) {
		return "", fmt.Errorf("image %s was found but does not match the specified platform %s", spec.Image, spec.Platform)
	}
	if _, dup := f.Containers[spec.Name]; dup {
		return "", fmt.Errorf("conflict: name %s already in use", spec.Name)
	}
	if spec.Network != nil && !predefinedNetwork(spec.Network.Name) {
		if _, ok := f.Networks[spec.Network.Name]; !ok {
			return "", fmt.Errorf("network %s not found", spec.Network.Name)
		}
	}
	f.nextID++
	f.nextIP++
	c := &Container{ID: fmt.Sprintf("c%03d", f.nextID), Spec: spec, IP: fmt.Sprintf("172.30.0.%d", f.nextIP+1)}
	f.Containers[spec.Name] = c
	return c.ID, nil
}

// freeHostPort returns a currently free TCP port on host (127.0.0.1 for "",
// 0.0.0.0 or ::, so a host without IPv6 can still run the tests).
func freeHostPort(host string) (int, error) {
	if host == "" || host == "0.0.0.0" || host == "::" {
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
	if c.Paused {
		f.mu.Unlock()
		return fmt.Errorf("cannot start a paused container, try unpause instead")
	}
	c.Running, c.started = true, true
	// Like the daemon, assign a free host port to every binding that asks
	// for host port 0 (a real free port, so a StartFn can listen on it).
	// Nothing is published from an internal network, so inspect then reports
	// no host port, as the daemon's does.
	if !f.NoAssignPorts && !f.onInternalNetwork(c) {
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

// onInternalNetwork reports whether c's primary network is an internal one.
// Called with f.mu held.
func (f *Fake) onInternalNetwork(c *Container) bool {
	return c.Spec.Network != nil && f.Networks[c.Spec.Network.Name].Internal
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
		st := "created"
		switch {
		case c.Paused:
			st = "paused"
		case c.Running:
			st = "running"
		case c.started:
			st = "exited"
		}
		out = append(out, engine.ContainerInfo{ID: c.ID, Name: name, Image: c.Spec.Image, State: st, Status: "Up", Labels: c.Spec.Labels})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *Fake) ContainerInspect(ctx context.Context, id string) (*engine.ContainerDetail, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.byIDOrName(id)
	if c == nil {
		return nil, fmt.Errorf("no such container %s", id)
	}
	d := &engine.ContainerDetail{ID: c.ID, Name: c.Spec.Name, Image: c.Spec.Image, Running: c.Running, Paused: c.Paused, ExitCode: c.ExitCode, IPs: map[string]string{}, Ports: map[string]engine.HostBinding{}}
	if c.Spec.Network != nil {
		d.IPs[c.Spec.Network.Name] = c.IP
	}
	for i, n := range c.Networks {
		d.IPs[n.Name] = fmt.Sprintf("10.99.%d.%d", i, f.nextIP)
	}
	for _, p := range c.Spec.Ports {
		proto := p.Protocol
		if proto == "" {
			proto = "tcp"
		}
		d.Ports[fmt.Sprintf("%d/%s", p.ContainerPort, proto)] = engine.HostBinding{IP: p.HostIP, Port: p.HostPort}
	}
	return d, nil
}

func (f *Fake) ContainerExec(ctx context.Context, id, command string, timeout time.Duration) (int, string, error) {
	if err := ctx.Err(); err != nil {
		return -1, "", err
	}
	f.mu.Lock()
	// Like the daemon, exec needs an existing, running, unpaused container.
	if c := f.byIDOrName(id); c == nil || !c.Running || c.Paused {
		f.mu.Unlock()
		switch {
		case c == nil:
			return -1, "", fmt.Errorf("no such container %s", id)
		case !c.Running:
			return -1, "", fmt.Errorf("container %s is not running", id)
		}
		return -1, "", fmt.Errorf("Container %s is paused, unpause the container before exec", id)
	}
	f.Execs = append(f.Execs, id+": "+command)
	f.ExecTimeouts = append(f.ExecTimeouts, timeout)
	f.Calls = append(f.Calls, "exec "+id+": "+command)
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
		c.Running, c.Paused = false, false
		c.ExitCode = code
	}
}

func (f *Fake) ContainerLogs(ctx context.Context, id string, _ int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
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

// ContainerWait blocks until the container is no longer running (see Exit)
// and returns its exit code, like the daemon's wait.
func (f *Fake) ContainerWait(ctx context.Context, id string) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return -1, err
		}
		f.mu.Lock()
		c := f.byIDOrName(id)
		if c == nil {
			f.mu.Unlock()
			return -1, fmt.Errorf("no such container %s", id)
		}
		running, code := c.Running, c.ExitCode
		f.mu.Unlock()
		if !running {
			return code, nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (f *Fake) NetworkEnsure(ctx context.Context, spec engine.NetworkSpec) (engine.Network, error) {
	if err := ctx.Err(); err != nil {
		return engine.Network{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Like the real engines, an existing network is returned as it is: its
	// settings are not updated to spec.
	if _, ok := f.Networks[spec.Name]; !ok {
		// As the real engines, a network vulnsuite creates carries the
		// managed label. Tests add f.Networks entries directly to stand
		// for networks someone else made (no label).
		labels := map[string]string{}
		for k, v := range spec.Labels {
			labels[k] = v
		}
		labels[engine.LabelManaged] = "true"
		spec.Labels = labels
		f.Networks[spec.Name] = spec
	}
	return fakeNetwork(f.Networks[spec.Name]), nil
}

func fakeNetwork(n engine.NetworkSpec) engine.Network {
	driver := n.Driver
	if driver == "" {
		driver = "bridge"
	}
	return engine.Network{ID: "net-" + n.Name, Driver: driver, Internal: n.Internal, Options: n.Options,
		Subnet: n.Subnet, Gateway: n.Gateway, Labels: n.Labels}
}

// NetworkInspect returns the network; exists is false when it is missing.
func (f *Fake) NetworkInspect(ctx context.Context, name string) (engine.Network, bool, error) {
	if err := ctx.Err(); err != nil {
		return engine.Network{}, false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.Networks[name]
	if !ok {
		return engine.Network{}, false, nil
	}
	return fakeNetwork(n), true, nil
}

func (f *Fake) NetworkExists(ctx context.Context, name string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
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

// predefinedNetwork reports whether name is one of the networks a daemon
// always has.
func predefinedNetwork(name string) bool {
	switch name {
	case "", "default", "bridge", "host", "none":
		return true
	}
	return false
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

// ContainerPause freezes a running container. Like dockerd, a missing,
// stopped or already paused container is an error.
func (f *Fake) ContainerPause(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.byIDOrName(id)
	switch {
	case c == nil:
		//lint:ignore ST1005 dockerd's message, verbatim
		return fmt.Errorf("No such container: %s", id)
	case !c.Running:
		return fmt.Errorf("container %s is not running", c.ID)
	case c.Paused:
		return fmt.Errorf("container %s is already paused", c.ID)
	}
	c.Paused = true
	f.Calls = append(f.Calls, "pause "+id)
	return nil
}

// ContainerUnpause thaws a paused container. Like dockerd, a missing or
// unpaused container is an error.
func (f *Fake) ContainerUnpause(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.byIDOrName(id)
	switch {
	case c == nil:
		//lint:ignore ST1005 dockerd's message, verbatim
		return fmt.Errorf("No such container: %s", id)
	case !c.Paused:
		return fmt.Errorf("Container %s is not paused", c.ID)
	}
	c.Paused = false
	f.Calls = append(f.Calls, "unpause "+id)
	return nil
}

// WriteFile puts a file, directory (mode with fs.ModeDir) or symlink (mode
// with fs.ModeSymlink, data its target) at the absolute path p in a created
// container, replacing what was there. Parent directories need not be written
// first: they exist, as 0755 directories, once something is in them. Call it
// after ContainerCreate, e.g. from StartFn or ExecFn to model a file the
// container's process writes.
func (f *Fake) WriteFile(container, p string, mode fs.FileMode, data string) error {
	if !path.IsAbs(p) {
		return fmt.Errorf("container path %q is not absolute", p)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.byIDOrName(container)
	if c == nil {
		return fmt.Errorf("no such container %s", container)
	}
	if c.Files == nil {
		c.Files = map[string]File{}
	}
	c.Files[path.Clean(p)] = File{Mode: mode, Data: data, ModTime: time.Now()}
	return nil
}

// lstat returns the file at the clean path p of c: a written one, or an
// implied parent directory. Called with f.mu held.
func lstat(c *Container, p string) (File, bool) {
	if file, ok := c.Files[p]; ok {
		return file, true
	}
	if p == "/" {
		return File{Mode: fs.ModeDir | 0o755}, true
	}
	for q := range c.Files {
		if strings.HasPrefix(q, p+"/") {
			return File{Mode: fs.ModeDir | 0o755}, true
		}
	}
	return File{}, false
}

// archivePath resolves a FileReader call to its container and clean path, or
// to the daemon's error. Called with f.mu held.
func (f *Fake) archivePath(id, p string) (*Container, string, File, error) {
	if !path.IsAbs(p) {
		return nil, "", File{}, fmt.Errorf("container path %q is not absolute", p)
	}
	c := f.byIDOrName(id)
	if c == nil {
		//lint:ignore ST1005 dockerd's message, verbatim
		return nil, "", File{}, fmt.Errorf("No such container: %s", id)
	}
	p = path.Clean(p)
	file, ok := lstat(c, p)
	if !ok {
		return nil, "", File{}, fmt.Errorf("%s in container %s: %w", p, id, fs.ErrNotExist)
	}
	return c, p, file, nil
}

// ContainerStatPath returns the mode of a file written with WriteFile (or of
// a directory implied by one). It works on a container in any state.
func (f *Fake) ContainerStatPath(ctx context.Context, id, p string) (fs.FileMode, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, _, file, err := f.archivePath(id, p)
	return file.Mode, err
}

// ContainerReadDir returns the regular files directly in dir. It packs dir
// into a tar the way dockerd's archive API does and reads it back with
// engine.DirFilesFromTar, as the real engines do.
func (f *Fake) ContainerReadDir(ctx context.Context, id, dir string, maxBytes int64) (map[string]engine.FileContent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	c, dir, file, err := f.archivePath(id, dir)
	if err != nil {
		f.mu.Unlock()
		return nil, err
	}
	if !file.Mode.IsDir() {
		f.mu.Unlock()
		return nil, fmt.Errorf("%s in container %s is not a directory (mode %s)", dir, id, file.Mode)
	}
	root := path.Base(dir)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(c.Files))
	for p := range c.Files {
		if strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/") {
			names = append(names, p)
		}
	}
	sort.Strings(names)
	for _, p := range names {
		file := c.Files[p]
		h := &tar.Header{Name: strings.TrimSuffix(root, "/") + "/" + strings.TrimPrefix(p, strings.TrimSuffix(dir, "/")+"/"), Mode: int64(file.Mode.Perm()),
			ModTime: file.ModTime, Format: tar.FormatPAX} // sub-second, unlike dockerd's whole seconds
		switch {
		case file.Mode.IsDir():
			h.Typeflag, h.Name = tar.TypeDir, h.Name+"/"
		case file.Mode&fs.ModeSymlink != 0:
			h.Typeflag, h.Linkname = tar.TypeSymlink, file.Data
		case file.Mode.IsRegular():
			h.Typeflag, h.Size = tar.TypeReg, int64(len(file.Data))
		default:
			continue
		}
		if err := tw.WriteHeader(h); err != nil {
			f.mu.Unlock()
			return nil, err
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = io.WriteString(tw, file.Data)
		}
	}
	_ = tw.Close()
	f.mu.Unlock()
	return engine.DirFilesFromTar(&buf, root, maxBytes)
}

var (
	_ engine.Engine     = (*Fake)(nil)
	_ engine.Pauser     = (*Fake)(nil)
	_ engine.FileReader = (*Fake)(nil)
)
