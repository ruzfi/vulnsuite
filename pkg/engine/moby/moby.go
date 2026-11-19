// Package moby implements engine.Engine with the official Moby (Docker) Go
// SDK, github.com/moby/moby/client. It is the default engine; the
// dependency-free engine/docker package speaks the same API with net/http
// and can be selected with `-engine api`.
package moby

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/authconfig"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/build"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/docker"
	"github.com/ruzfi/vulnsuite/pkg/engine/registryauth"
)

// Engine wraps a moby client.
type Engine struct {
	cli  *client.Client
	host string
}

// New connects to host, negotiating the API version with the daemon. An
// empty host resolves like the docker CLI and the built-in api engine:
// DOCKER_HOST (with DOCKER_TLS_VERIFY / DOCKER_CERT_PATH), then the context
// named by DOCKER_CONTEXT or currentContext, then the local socket defaults
// (including the Docker Desktop, OrbStack and Colima per-user sockets).
func New(host string) (*Engine, error) {
	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	switch {
	case host != "":
		opts = append(opts, client.WithHost(host))
	case os.Getenv("DOCKER_HOST") == "":
		// FromEnv has nothing to go on: resolve the context / socket the
		// way the docker CLI does.
		ep, err := docker.ResolveEndpoint()
		if err != nil {
			return nil, err
		}
		epOpts, err := endpointOpts(ep)
		if err != nil {
			return nil, err
		}
		opts = append(opts, epOpts...)
	}
	cli, err := client.New(opts...)
	if err != nil {
		return nil, err
	}
	return &Engine{cli: cli, host: cli.DaemonHost()}, nil
}

// endpointOpts turns a resolved endpoint into SDK options. Its TLS settings
// apply to a tcp:// host only, as in the api engine; a socket ignores them.
func endpointOpts(ep docker.Endpoint) ([]client.Opt, error) {
	u, err := url.Parse(ep.Host)
	if err != nil {
		return nil, fmt.Errorf("docker endpoint %q: %w", ep.Host, err)
	}
	files := ep.TLS
	if files == nil || u.Scheme != "tcp" {
		return []client.Opt{client.WithHost(ep.Host)}, nil
	}
	cfg, err := files.TLSConfig(u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("TLS for %s: %w", ep.Host, err)
	}
	// WithHost configures the dialer on the transport WithHTTPClient sets,
	// so it must come second.
	hc := &http.Client{Transport: &http.Transport{
		TLSClientConfig: cfg,
		MaxIdleConns:    6,
		IdleConnTimeout: 30 * time.Second,
	}, CheckRedirect: client.CheckRedirect}
	return []client.Opt{client.WithHTTPClient(hc), client.WithHost(ep.Host)}, nil
}

// Client exposes the underlying SDK client.
func (e *Engine) Client() *client.Client { return e.cli }

// Host returns the daemon address in use.
func (e *Engine) Host() string { return e.host }

// Ping checks connectivity and returns the daemon version.
func (e *Engine) Ping(ctx context.Context) (string, error) {
	v, err := e.cli.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		return "", fmt.Errorf("cannot reach the Docker daemon at %s (is Docker running? set DOCKER_HOST to point elsewhere): %w", e.host, err)
	}
	return fmt.Sprintf("%s (api %s, %s/%s)", v.Version, v.APIVersion, v.Os, v.Arch), nil
}

// Info returns the daemon OS/arch.
func (e *Engine) Info(ctx context.Context) (engine.HostInfo, error) {
	v, err := e.cli.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		return engine.HostInfo{}, err
	}
	return engine.HostInfo{OS: v.Os, Arch: v.Arch}, nil
}

// -- images -------------------------------------------------------------------

func (e *Engine) ImageExists(ctx context.Context, ref, platform string) (bool, error) {
	img, err := e.cli.ImageInspect(ctx, ref)
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if engine.PlatformMatches(platform, img.Os, img.Architecture, img.Variant) {
		return true, nil
	}
	// A multi-platform store (containerd) reports the host's variant by
	// default; ask for the wanted one (API 1.49+). An older daemon, or one
	// without that platform's content, means it has to be pulled.
	p, err := parsePlatform(platform)
	if err != nil {
		return false, err
	}
	if !apiAtLeast(e.cli.ClientVersion(), 1, 49) {
		return false, nil
	}
	img, err = e.cli.ImageInspect(ctx, ref, client.ImageInspectWithPlatform(&p))
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return engine.PlatformMatches(platform, img.Os, img.Architecture, img.Variant), nil
}

func (e *Engine) ImagePull(ctx context.Context, ref, platform string, out io.Writer) error {
	po := client.ImagePullOptions{RegistryAuth: registryauth.ForContext(ctx, ref)}
	if platform != "" {
		p, err := parsePlatform(platform)
		if err != nil {
			return err
		}
		po.Platforms = []ocispec.Platform{p}
	}
	resp, err := e.cli.ImagePull(ctx, ref, po)
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	if err := drain(ctx, messages(ctx, resp), out); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	return nil
}

func (e *Engine) ImageBuild(ctx context.Context, opts engine.BuildOptions, out io.Writer) error {
	args := map[string]*string{}
	for k, v := range opts.BuildArgs {
		v := v
		args[k] = &v
	}
	bo := client.ImageBuildOptions{
		Tags:        opts.Tags,
		Dockerfile:  opts.Dockerfile,
		BuildArgs:   args,
		NoCache:     opts.NoCache,
		PullParent:  opts.Pull,
		Labels:      opts.Labels,
		Remove:      true,
		ForceRemove: true,
		Version:     build.BuilderV1,
		AuthConfigs: authConfigs(ctx),
	}
	if opts.Platform != "" {
		p, err := parsePlatform(opts.Platform)
		if err != nil {
			return err
		}
		bo.Platforms = append(bo.Platforms, p)
	}
	resp, err := e.cli.ImageBuild(ctx, opts.Context, bo)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return drainReader(resp.Body, out)
}

func (e *Engine) ImageTag(ctx context.Context, source, target string) error {
	_, err := e.cli.ImageTag(ctx, client.ImageTagOptions{Source: source, Target: target})
	return err
}

func (e *Engine) ImagePush(ctx context.Context, ref string, out io.Writer) error {
	auth := registryauth.ForPushContext(ctx, ref)
	if auth == "" {
		auth, _ = authconfig.Encode(registry.AuthConfig{})
	}
	resp, err := e.cli.ImagePush(ctx, ref, client.ImagePushOptions{RegistryAuth: auth})
	if err != nil {
		return fmt.Errorf("push %s: %w", ref, err)
	}
	if err := drain(ctx, messages(ctx, resp), out); err != nil {
		return fmt.Errorf("push %s: %w", ref, err)
	}
	return nil
}

func (e *Engine) ImageRemove(ctx context.Context, ref string, force bool) error {
	_, err := e.cli.ImageRemove(ctx, ref, client.ImageRemoveOptions{Force: force})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	return err
}

func (e *Engine) ImageList(ctx context.Context, repoPrefix string) ([]string, error) {
	res, err := e.cli.ImageList(ctx, client.ImageListOptions{})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, im := range res.Items {
		for _, t := range im.RepoTags {
			if strings.HasPrefix(t, repoPrefix) {
				out = append(out, t)
			}
		}
	}
	return out, nil
}

// -- containers -----------------------------------------------------------------

func (e *Engine) ContainerCreate(ctx context.Context, spec engine.ContainerSpec) (string, error) {
	cfg := &container.Config{Image: spec.Image, Cmd: spec.Cmd, Env: spec.Env, User: spec.User, Labels: spec.Labels}
	hc := &container.HostConfig{
		CapAdd:      spec.CapAdd,
		CapDrop:     spec.CapDrop,
		SecurityOpt: spec.SecurityOpt,
		Binds:       spec.Binds,
		AutoRemove:  spec.AutoRemove,
	}
	for _, d := range spec.Devices {
		in, perm := d.PathInContainer, d.Permissions
		if in == "" {
			in = d.PathOnHost
		}
		if perm == "" {
			perm = "rwm"
		}
		hc.Devices = append(hc.Devices, container.DeviceMapping{PathOnHost: d.PathOnHost, PathInContainer: in, CgroupPermissions: perm})
	}
	if len(spec.Ports) > 0 {
		cfg.ExposedPorts = network.PortSet{}
		hc.PortBindings = network.PortMap{}
		for _, p := range spec.Ports {
			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}
			port, err := network.ParsePort(fmt.Sprintf("%d/%s", p.ContainerPort, proto))
			if err != nil {
				return "", err
			}
			cfg.ExposedPorts[port] = struct{}{}
			b := network.PortBinding{}
			if p.HostIP != "" {
				addr, err := netip.ParseAddr(p.HostIP)
				if err != nil {
					return "", fmt.Errorf("bind address %q: %w", p.HostIP, err)
				}
				b.HostIP = addr
			}
			if p.HostPort > 0 {
				b.HostPort = strconv.Itoa(p.HostPort)
			}
			hc.PortBindings[port] = append(hc.PortBindings[port], b)
		}
	}
	var nc *network.NetworkingConfig
	if spec.Network != nil {
		hc.NetworkMode = container.NetworkMode(spec.Network.Name)
		ep := &network.EndpointSettings{Aliases: spec.Network.Aliases}
		if spec.Network.IPv4 != "" {
			addr, err := netip.ParseAddr(spec.Network.IPv4)
			if err != nil {
				return "", fmt.Errorf("ip %q: %w", spec.Network.IPv4, err)
			}
			ep.IPAMConfig = &network.EndpointIPAMConfig{IPv4Address: addr}
		}
		nc = &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{spec.Network.Name: ep}}
	}
	co := client.ContainerCreateOptions{Name: spec.Name, Config: cfg, HostConfig: hc, NetworkingConfig: nc}
	if spec.Platform != "" {
		p, err := parsePlatform(spec.Platform)
		if err != nil {
			return "", err
		}
		co.Platform = &p
	}
	res, err := e.cli.ContainerCreate(ctx, co)
	if err != nil {
		return "", err
	}
	return res.ID, nil
}

func (e *Engine) ContainerStart(ctx context.Context, id string) error {
	_, err := e.cli.ContainerStart(ctx, id, client.ContainerStartOptions{})
	return err
}

func (e *Engine) ContainerRemove(ctx context.Context, id string) error {
	_, err := e.cli.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	return err
}

func (e *Engine) ContainerList(ctx context.Context, all bool, namePrefix string) ([]engine.ContainerInfo, error) {
	opts := client.ContainerListOptions{All: all}
	if namePrefix != "" {
		opts.Filters = client.Filters{}.Add("name", "^/"+namePrefix)
	}
	res, err := e.cli.ContainerList(ctx, opts)
	if err != nil {
		return nil, err
	}
	var out []engine.ContainerInfo
	for _, c := range res.Items {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		if namePrefix != "" && !strings.HasPrefix(name, namePrefix) {
			continue
		}
		out = append(out, engine.ContainerInfo{ID: c.ID, Name: name, Image: c.Image, State: string(c.State), Status: c.Status, Labels: c.Labels})
	}
	return out, nil
}

func (e *Engine) ContainerInspect(ctx context.Context, id string) (*engine.ContainerDetail, error) {
	res, err := e.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return nil, err
	}
	c := res.Container
	out := &engine.ContainerDetail{ID: c.ID, Name: strings.TrimPrefix(c.Name, "/"), IPs: map[string]string{}, Ports: map[string]engine.HostBinding{}}
	if c.Config != nil {
		out.Image = c.Config.Image
	}
	if c.State != nil {
		out.Running = c.State.Running
		out.ExitCode = c.State.ExitCode
	}
	if c.NetworkSettings != nil {
		for name, n := range c.NetworkSettings.Networks {
			if n != nil && n.IPAddress.IsValid() {
				out.IPs[name] = n.IPAddress.String()
			}
		}
		for port, bindings := range c.NetworkSettings.Ports {
			if len(bindings) > 0 {
				if p, err := strconv.Atoi(bindings[0].HostPort); err == nil {
					var ip string
					if bindings[0].HostIP.IsValid() {
						ip = bindings[0].HostIP.String()
					}
					out.Ports[port.String()] = engine.HostBinding{IP: ip, Port: p}
				}
			}
		}
	}
	return out, nil
}

func (e *Engine) ContainerExec(ctx context.Context, id, command string, timeout time.Duration) (int, string, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	created, err := e.cli.ExecCreate(ctx, id, client.ExecCreateOptions{AttachStdout: true, AttachStderr: true, Cmd: []string{"sh", "-c", command}})
	if err != nil {
		return -1, "", err
	}
	att, err := e.cli.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		return -1, "", err
	}
	// The hijacked connection does not watch ctx once attached; close it when
	// the timeout (or the caller) cancels so a hung command cannot block here.
	stopClose := context.AfterFunc(ctx, att.Close)
	defer stopClose()
	out := &engine.CappedBuffer{Max: execOutputCap}
	// Read to EOF (the stream ends when the process exits), keeping only the
	// first execOutputCap bytes: stopping early would inspect a still-running
	// exec and report its exit code as 0.
	_, _ = stdcopy.StdCopy(out, out, att.Reader)
	att.Close()
	if err := ctx.Err(); err != nil {
		return -1, out.String(), fmt.Errorf("exec timed out: %w", err)
	}
	for {
		insp, err := e.cli.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
		if err != nil {
			return -1, out.String(), err
		}
		if !insp.Running {
			return insp.ExitCode, out.String(), nil
		}
		// The stream can close a moment before the daemon records the exit.
		select {
		case <-ctx.Done():
			return -1, out.String(), fmt.Errorf("exec timed out: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// execOutputCap bounds how much exec output is kept.
const execOutputCap = 1 << 20

func (e *Engine) ContainerLogs(ctx context.Context, id string, tail int) (string, error) {
	opts := client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true}
	if tail > 0 {
		opts.Tail = strconv.Itoa(tail)
	}
	rc, err := e.cli.ContainerLogs(ctx, id, opts)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	var out strings.Builder
	if _, err := stdcopy.StdCopy(&out, &out, io.LimitReader(rc, 4<<20)); err != nil {
		// a TTY container streams raw bytes without frame headers
		raw, _ := io.ReadAll(io.LimitReader(rc, 4<<20))
		return out.String() + string(raw), nil
	}
	return out.String(), nil
}

func (e *Engine) ContainerWait(ctx context.Context, id string) (int, error) {
	res := e.cli.ContainerWait(ctx, id, client.ContainerWaitOptions{})
	select {
	case r := <-res.Result:
		if r.Error != nil {
			return int(r.StatusCode), errors.New(r.Error.Message)
		}
		return int(r.StatusCode), nil
	case err := <-res.Error:
		return -1, err
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

// -- networks -------------------------------------------------------------------

func (e *Engine) NetworkExists(ctx context.Context, name string) (bool, error) {
	_, err := e.cli.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
	if err == nil {
		return true, nil
	}
	if cerrdefs.IsNotFound(err) {
		return false, nil
	}
	return false, err
}

// NetworkEnsure creates the network when missing and returns it as the
// daemon reports it; an existing network is returned with its own settings.
func (e *Engine) NetworkEnsure(ctx context.Context, spec engine.NetworkSpec) (engine.Network, error) {
	if res, err := e.cli.NetworkInspect(ctx, spec.Name, client.NetworkInspectOptions{}); err == nil {
		return toNetwork(res.Network), nil
	} else if !cerrdefs.IsNotFound(err) {
		return engine.Network{}, err
	}
	driver := spec.Driver
	if driver == "" {
		driver = "bridge"
	}
	opts := client.NetworkCreateOptions{Driver: driver, Internal: spec.Internal, Options: spec.Options,
		Labels: map[string]string{"dev.vulnsuite.managed": "true"}}
	if spec.Subnet != "" {
		prefix, err := netip.ParsePrefix(spec.Subnet)
		if err != nil {
			return engine.Network{}, fmt.Errorf("subnet %q: %w", spec.Subnet, err)
		}
		cfg := network.IPAMConfig{Subnet: prefix}
		if spec.Gateway != "" {
			gw, err := netip.ParseAddr(spec.Gateway)
			if err != nil {
				return engine.Network{}, fmt.Errorf("gateway %q: %w", spec.Gateway, err)
			}
			cfg.Gateway = gw
		}
		opts.IPAM = &network.IPAM{Driver: "default", Config: []network.IPAMConfig{cfg}}
	}
	if _, err := e.cli.NetworkCreate(ctx, spec.Name, opts); err != nil {
		// A concurrent run created it between our inspect and create: use
		// that one (the caller checks its settings).
		if cerrdefs.IsConflict(err) {
			if again, ierr := e.cli.NetworkInspect(ctx, spec.Name, client.NetworkInspectOptions{}); ierr == nil {
				return toNetwork(again.Network), nil
			}
		}
		return engine.Network{}, err
	}
	// Read back what the daemon made, so the caller sees the same fields for
	// a new network as for an existing one.
	res, err := e.cli.NetworkInspect(ctx, spec.Name, client.NetworkInspectOptions{})
	if err != nil {
		return engine.Network{}, fmt.Errorf("inspect new network %s: %w", spec.Name, err)
	}
	return toNetwork(res.Network), nil
}

func toNetwork(n network.Inspect) engine.Network {
	out := engine.Network{ID: n.ID, Driver: n.Driver, Internal: n.Internal, Options: n.Options}
	if len(n.IPAM.Config) > 0 {
		c := n.IPAM.Config[0]
		if c.Subnet.IsValid() {
			out.Subnet = c.Subnet.String()
		}
		if c.Gateway.IsValid() {
			out.Gateway = c.Gateway.String()
		}
	}
	return out
}

func (e *Engine) NetworkRemove(ctx context.Context, name string) error {
	_, err := e.cli.NetworkRemove(ctx, name, client.NetworkRemoveOptions{})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	return err
}

func (e *Engine) NetworkConnect(ctx context.Context, networkName, container string, aliases []string) error {
	_, err := e.cli.NetworkConnect(ctx, networkName, client.NetworkConnectOptions{
		Container:      container,
		EndpointConfig: &network.EndpointSettings{Aliases: aliases},
	})
	return err
}

// -- helpers --------------------------------------------------------------------

func authConfigs(ctx context.Context) map[string]registry.AuthConfig {
	out := map[string]registry.AuthConfig{}
	for k, c := range registryauth.ConfigsContext(ctx) {
		out[k] = registry.AuthConfig{Username: c.Username, Password: c.Password, ServerAddress: c.ServerAddress, IdentityToken: c.IdentityToken}
	}
	return out
}

// apiAtLeast reports whether the negotiated API version v ("1.51") is at least
// major.minor. An empty or unparsable version (negotiation not done) counts
// as recent enough: the SDK then checks the requirement itself.
func apiAtLeast(v string, major, minor int) bool {
	a, b, ok := strings.Cut(v, ".")
	if !ok {
		return true
	}
	ma, err1 := strconv.Atoi(a)
	mi, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return true
	}
	return ma > major || (ma == major && mi >= minor)
}

func parsePlatform(s string) (ocispec.Platform, error) {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ocispec.Platform{}, fmt.Errorf("platform %q must look like linux/amd64", s)
	}
	p := ocispec.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) > 2 {
		p.Variant = parts[2]
	}
	return p, nil
}

// streamMessage is one line of a JSON progress stream (build, pull, push).
// Daemons have reported failures in two forms, an "errorDetail" object and a
// top-level "error" string (dockerd sends both). The Moby API module's
// jsonstream.Message dropped "error", so it is decoded here too: a daemon or
// proxy that sends only that form must not have its failure read as success.
type streamMessage struct {
	jsonstream.Message
	ErrorMessage string `json:"error,omitempty"`
}

// err returns the failure m reports, or nil.
func (m streamMessage) err() error {
	if m.Error == nil && m.ErrorMessage == "" {
		return nil
	}
	msg := m.ErrorMessage
	if m.Error != nil && strings.TrimSpace(m.Error.Message) != "" {
		msg = m.Error.Message
	}
	if msg = strings.TrimSpace(msg); msg == "" {
		msg = "the daemon reported an error with no message"
	}
	return errors.New(msg)
}

// messages decodes a pull/push response as a sequence of streamMessage, like
// the SDK's JSONMessages (which would drop the "error" form): rc is closed
// when the sequence ends or ctx is cancelled.
func messages(ctx context.Context, rc io.ReadCloser) iter.Seq2[streamMessage, error] {
	return func(yield func(streamMessage, error) bool) {
		stop := context.AfterFunc(ctx, func() { _ = rc.Close() })
		defer func() {
			stop()
			_ = rc.Close()
		}()
		dec := json.NewDecoder(rc)
		for {
			var m streamMessage
			if err := dec.Decode(&m); err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				// A read cut short by cancellation reports the cancellation,
				// not the closed body.
				if cerr := ctx.Err(); cerr != nil {
					err = cerr
				}
				yield(streamMessage{}, err)
				return
			}
			if !yield(m, nil) {
				return
			}
		}
	}
}

// drain consumes a pull/push message stream, writing status changes to out.
func drain(ctx context.Context, msgs iter.Seq2[streamMessage, error], out io.Writer) error {
	var last string
	var failed error
	msgs(func(m streamMessage, err error) bool {
		if err != nil {
			failed = err
			return false
		}
		if err := m.err(); err != nil {
			failed = err
			return false
		}
		if out != nil && m.Status != "" && m.Progress == nil {
			line := m.Status
			if m.ID != "" {
				line = m.ID + ": " + line
			}
			if line != last {
				io.WriteString(out, line+"\n")
				last = line
			}
		}
		return ctx.Err() == nil
	})
	if failed == nil {
		// The stream stopped because ctx was cancelled (or the iterator itself
		// gave up on it): the pull/push did not finish, so it is not a success.
		failed = ctx.Err()
	}
	return failed
}

// drainReader consumes a build stream.
func drainReader(r io.Reader, out io.Writer) error {
	dec := json.NewDecoder(r)
	for {
		var m streamMessage
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading build stream: %w", err)
		}
		if err := m.err(); err != nil {
			return err
		}
		if out != nil && m.Stream != "" {
			io.WriteString(out, m.Stream)
		}
	}
}

var _ engine.Engine = (*Engine)(nil)
