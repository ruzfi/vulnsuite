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
	"net/netip"
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
	"github.com/ruzfi/vulnsuite/pkg/engine/registryauth"
)

// Engine wraps a moby client.
type Engine struct {
	cli  *client.Client
	host string
}

// New connects to host (empty = DOCKER_HOST / the local socket), negotiating
// the API version with the daemon.
func New(host string) (*Engine, error) {
	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	if host != "" {
		opts = append(opts, client.WithHost(host))
	}
	cli, err := client.New(opts...)
	if err != nil {
		return nil, err
	}
	return &Engine{cli: cli, host: cli.DaemonHost()}, nil
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

func (e *Engine) ImageExists(ctx context.Context, ref string) (bool, error) {
	_, err := e.cli.ImageInspect(ctx, ref)
	if err == nil {
		return true, nil
	}
	if cerrdefs.IsNotFound(err) {
		return false, nil
	}
	return false, err
}

func (e *Engine) ImagePull(ctx context.Context, ref string, out io.Writer) error {
	resp, err := e.cli.ImagePull(ctx, ref, client.ImagePullOptions{RegistryAuth: registryauth.For(ref)})
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	if err := drain(ctx, resp.JSONMessages(ctx), out); err != nil {
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
		AuthConfigs: authConfigs(),
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
	auth := registryauth.For(ref)
	if auth == "" {
		auth, _ = authconfig.Encode(registry.AuthConfig{})
	}
	resp, err := e.cli.ImagePush(ctx, ref, client.ImagePushOptions{RegistryAuth: auth})
	if err != nil {
		return fmt.Errorf("push %s: %w", ref, err)
	}
	if err := drain(ctx, resp.JSONMessages(ctx), out); err != nil {
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
	res, err := e.cli.ContainerCreate(ctx, client.ContainerCreateOptions{Name: spec.Name, Config: cfg, HostConfig: hc, NetworkingConfig: nc})
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
	var out strings.Builder
	_, _ = stdcopy.StdCopy(&out, &out, io.LimitReader(att.Reader, 1<<20))
	att.Close()
	insp, err := e.cli.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
	if err != nil {
		return -1, out.String(), err
	}
	return insp.ExitCode, out.String(), nil
}

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

func (e *Engine) NetworkEnsure(ctx context.Context, spec engine.NetworkSpec) (string, error) {
	if res, err := e.cli.NetworkInspect(ctx, spec.Name, client.NetworkInspectOptions{}); err == nil {
		return res.Network.ID, nil
	} else if !cerrdefs.IsNotFound(err) {
		return "", err
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
			return "", fmt.Errorf("subnet %q: %w", spec.Subnet, err)
		}
		cfg := network.IPAMConfig{Subnet: prefix}
		if spec.Gateway != "" {
			gw, err := netip.ParseAddr(spec.Gateway)
			if err != nil {
				return "", fmt.Errorf("gateway %q: %w", spec.Gateway, err)
			}
			cfg.Gateway = gw
		}
		opts.IPAM = &network.IPAM{Driver: "default", Config: []network.IPAMConfig{cfg}}
	}
	res, err := e.cli.NetworkCreate(ctx, spec.Name, opts)
	if err != nil {
		return "", err
	}
	return res.ID, nil
}

func (e *Engine) NetworkRemove(ctx context.Context, name string) error {
	_, err := e.cli.NetworkRemove(ctx, name, client.NetworkRemoveOptions{})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	return err
}

// -- helpers --------------------------------------------------------------------

func authConfigs() map[string]registry.AuthConfig {
	out := map[string]registry.AuthConfig{}
	for k, c := range registryauth.Configs() {
		out[k] = registry.AuthConfig{Username: c.Username, Password: c.Password, ServerAddress: c.ServerAddress, IdentityToken: c.IdentityToken}
	}
	return out
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

// drain consumes a pull/push message stream, writing status changes to out.
func drain(ctx context.Context, msgs func(func(jsonstream.Message, error) bool), out io.Writer) error {
	var last string
	var failed error
	msgs(func(m jsonstream.Message, err error) bool {
		if err != nil {
			failed = err
			return false
		}
		if m.Error != nil {
			failed = errors.New(strings.TrimSpace(m.Error.Message))
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
	return failed
}

// drainReader consumes a build stream.
func drainReader(r io.Reader, out io.Writer) error {
	dec := json.NewDecoder(r)
	for {
		var m jsonstream.Message
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading build stream: %w", err)
		}
		if m.Error != nil {
			return errors.New(strings.TrimSpace(m.Error.Message))
		}
		if out != nil && m.Stream != "" {
			io.WriteString(out, m.Stream)
		}
	}
}

var _ engine.Engine = (*Engine)(nil)
