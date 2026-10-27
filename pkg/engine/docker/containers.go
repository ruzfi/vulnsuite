package docker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type createBody struct {
	Image        string              `json:"Image"`
	Cmd          []string            `json:"Cmd,omitempty"`
	Env          []string            `json:"Env,omitempty"`
	User         string              `json:"User,omitempty"`
	Labels       map[string]string   `json:"Labels,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	HostConfig   struct {
		NetworkMode  string                   `json:"NetworkMode,omitempty"`
		PortBindings map[string][]portBinding `json:"PortBindings,omitempty"`
		CapAdd       []string                 `json:"CapAdd,omitempty"`
		CapDrop      []string                 `json:"CapDrop,omitempty"`
		SecurityOpt  []string                 `json:"SecurityOpt,omitempty"`
		Binds        []string                 `json:"Binds,omitempty"`
		AutoRemove   bool                     `json:"AutoRemove,omitempty"`
		Devices      []struct {
			PathOnHost        string `json:"PathOnHost"`
			PathInContainer   string `json:"PathInContainer"`
			CgroupPermissions string `json:"CgroupPermissions"`
		} `json:"Devices,omitempty"`
	} `json:"HostConfig"`
	NetworkingConfig *networkingConfig `json:"NetworkingConfig,omitempty"`
}

type ipamConfig struct {
	IPv4Address string `json:"IPv4Address,omitempty"`
}

type endpointConfig struct {
	Aliases    []string    `json:"Aliases,omitempty"`
	IPAMConfig *ipamConfig `json:"IPAMConfig,omitempty"`
}

type networkingConfig struct {
	EndpointsConfig map[string]endpointConfig `json:"EndpointsConfig"`
}

// ContainerCreate creates (but does not start) a container.
func (c *Client) ContainerCreate(ctx context.Context, spec engine.ContainerSpec) (string, error) {
	body := createBody{Image: spec.Image, Cmd: spec.Cmd, Env: spec.Env, User: spec.User, Labels: spec.Labels}
	hc := &body.HostConfig
	hc.CapAdd, hc.CapDrop, hc.SecurityOpt, hc.Binds, hc.AutoRemove = spec.CapAdd, spec.CapDrop, spec.SecurityOpt, spec.Binds, spec.AutoRemove
	for _, d := range spec.Devices {
		perm := d.Permissions
		if perm == "" {
			perm = "rwm"
		}
		in := d.PathInContainer
		if in == "" {
			in = d.PathOnHost
		}
		hc.Devices = append(hc.Devices, struct {
			PathOnHost        string `json:"PathOnHost"`
			PathInContainer   string `json:"PathInContainer"`
			CgroupPermissions string `json:"CgroupPermissions"`
		}{d.PathOnHost, in, perm})
	}
	if len(spec.Ports) > 0 {
		body.ExposedPorts = map[string]struct{}{}
		hc.PortBindings = map[string][]portBinding{}
		for _, p := range spec.Ports {
			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}
			key := fmt.Sprintf("%d/%s", p.ContainerPort, proto)
			body.ExposedPorts[key] = struct{}{}
			hp := ""
			if p.HostPort > 0 {
				hp = strconv.Itoa(p.HostPort)
			}
			hc.PortBindings[key] = append(hc.PortBindings[key], portBinding{HostIP: p.HostIP, HostPort: hp})
		}
	}
	if spec.Network != nil {
		hc.NetworkMode = spec.Network.Name
		ep := endpointConfig{Aliases: spec.Network.Aliases}
		if spec.Network.IPv4 != "" {
			ep.IPAMConfig = &ipamConfig{IPv4Address: spec.Network.IPv4}
		}
		body.NetworkingConfig = &networkingConfig{EndpointsConfig: map[string]endpointConfig{spec.Network.Name: ep}}
	}
	q := url.Values{}
	if spec.Name != "" {
		q.Set("name", spec.Name)
	}
	var out struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/containers/create", q, body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// ContainerStart starts a container.
func (c *Client) ContainerStart(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil, nil, nil)
}

// ContainerRemove force-removes a container; missing is not an error.
func (c *Client) ContainerRemove(ctx context.Context, id string) error {
	q := url.Values{"force": {"1"}, "v": {"1"}}
	err := c.doJSON(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id), q, nil, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// ContainerList lists containers whose name starts with namePrefix.
func (c *Client) ContainerList(ctx context.Context, all bool, namePrefix string) ([]engine.ContainerInfo, error) {
	q := url.Values{}
	if all {
		q.Set("all", "1")
	}
	if namePrefix != "" {
		f, _ := json.Marshal(map[string][]string{"name": {"^/" + namePrefix}})
		q.Set("filters", string(f))
	}
	var rows []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		Image  string            `json:"Image"`
		State  string            `json:"State"`
		Status string            `json:"Status"`
		Labels map[string]string `json:"Labels"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/containers/json", q, nil, &rows); err != nil {
		return nil, err
	}
	var out []engine.ContainerInfo
	for _, r := range rows {
		name := ""
		if len(r.Names) > 0 {
			name = strings.TrimPrefix(r.Names[0], "/")
		}
		if namePrefix != "" && !strings.HasPrefix(name, namePrefix) {
			continue // the name filter is a regex-ish substring match; be exact
		}
		out = append(out, engine.ContainerInfo{ID: r.ID, Name: name, Image: r.Image, State: r.State, Status: r.Status, Labels: r.Labels})
	}
	return out, nil
}

// ContainerInspect returns network addresses, state and port bindings.
func (c *Client) ContainerInspect(ctx context.Context, id string) (*engine.ContainerDetail, error) {
	var d struct {
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		State struct {
			Running  bool `json:"Running"`
			ExitCode int  `json:"ExitCode"`
		} `json:"State"`
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
			Ports map[string][]portBinding `json:"Ports"`
		} `json:"NetworkSettings"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil, &d); err != nil {
		return nil, err
	}
	out := &engine.ContainerDetail{
		ID: d.ID, Name: strings.TrimPrefix(d.Name, "/"), Image: d.Config.Image,
		Running: d.State.Running, ExitCode: d.State.ExitCode,
		IPs: map[string]string{}, Ports: map[string]engine.HostBinding{},
	}
	for name, n := range d.NetworkSettings.Networks {
		if n.IPAddress != "" {
			out.IPs[name] = n.IPAddress
		}
	}
	for key, bindings := range d.NetworkSettings.Ports {
		if len(bindings) > 0 {
			if p, err := strconv.Atoi(bindings[0].HostPort); err == nil {
				out.Ports[key] = engine.HostBinding{IP: bindings[0].HostIP, Port: p}
			}
		}
	}
	return out, nil
}

// ContainerExec runs `sh -c command` inside the container.
func (c *Client) ContainerExec(ctx context.Context, id, command string, timeout time.Duration) (int, string, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var created struct {
		ID string `json:"Id"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/exec", nil, map[string]any{
		"AttachStdout": true, "AttachStderr": true, "Cmd": []string{"sh", "-c", command},
	}, &created)
	if err != nil {
		return -1, "", err
	}
	resp, err := c.do(ctx, http.MethodPost, "/exec/"+created.ID+"/start", nil,
		strings.NewReader(`{"Detach":false,"Tty":false}`), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return -1, "", err
	}
	out := demux(resp.Body)
	resp.Body.Close()
	var insp struct {
		ExitCode int `json:"ExitCode"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/exec/"+created.ID+"/json", nil, nil, &insp); err != nil {
		return -1, out, err
	}
	return insp.ExitCode, out, nil
}

// demux decodes the Docker stream multiplexing format (8-byte frame headers).
func demux(r io.Reader) string {
	var b strings.Builder
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			break
		}
		n := binary.BigEndian.Uint32(hdr[4:])
		if n == 0 {
			continue
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			b.Write(buf)
			break
		}
		b.Write(buf)
		if b.Len() > 1<<20 {
			break
		}
	}
	return b.String()
}

// ContainerLogs returns the last `tail` lines of stdout+stderr.
func (c *Client) ContainerLogs(ctx context.Context, id string, tail int) (string, error) {
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}}
	if tail > 0 {
		q.Set("tail", strconv.Itoa(tail))
	}
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs", q, nil, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/vnd.docker.multiplexed-stream") ||
		resp.Header.Get("Content-Type") == "application/vnd.docker.raw-stream" {
		return demux(resp.Body), nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	s := string(b)
	// older daemons send the multiplexed stream without a telling content type
	if len(s) >= 8 && (s[0] == 1 || s[0] == 2) && s[1] == 0 && s[2] == 0 && s[3] == 0 {
		return demux(strings.NewReader(s)), nil
	}
	return s, nil
}

// ContainerWait blocks until the container exits.
func (c *Client) ContainerWait(ctx context.Context, id string) (int, error) {
	var out struct {
		StatusCode int `json:"StatusCode"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/wait", nil, nil, &out); err != nil {
		return -1, err
	}
	return out.StatusCode, nil
}
